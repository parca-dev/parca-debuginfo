// Copyright (c) 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/klauspost/compress/zstd"
	grun "github.com/oklog/run"
	"github.com/parca-dev/parca-agent/reporter/elfwriter"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rzajac/flexbuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	LogLevelDebug = "debug"
)

type flags struct {
	LogLevel string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`

	Upload struct {
		StoreAddress       string            `kong:"required,help='gRPC address to sends symbols to.'"`
		BearerToken        string            `kong:"help='Bearer token to authenticate with store.',env='PARCA_DEBUGINFO_BEARER_TOKEN'"`
		BearerTokenFile    string            `kong:"help='File to read bearer token from to authenticate with store.'"`
		Insecure           bool              `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
		InsecureSkipVerify bool              `kong:"help='Skip TLS certificate verification.'"`
		GRPCHeaders        map[string]string `kong:"help='Additional gRPC headers to send with each request (key=value pairs).'"`
		NoExtract          bool              `kong:"help='Do not extract debug information from binaries, just upload the binary as is.'"`
		NoInitiate         bool              `kong:"help='Do not initiate the upload, just check if it should be initiated.'"`
		Force              bool              `kong:"help='Force upload even if the Build ID is already uploaded.'"`
		Type               string            `kong:"enum='debuginfo,executable,sources',help='Type of the debug information to upload.',default='debuginfo'"`
		BuildID            string            `kong:"help='Build ID of the binary to upload.'"`

		Path string `kong:"required,arg,name='path',help='Paths to upload.',type:'path'"`
	} `cmd:"" help:"Upload debug information files."`

	Extract struct {
		OutputDir string `kong:"help='Output directory path to use for extracted debug information files.',default='out'"`

		Paths []string `kong:"required,arg,name='path',help='Paths to extract debug information.',type:'path'"`
	} `cmd:"" help:"Extract debug information."`

	Buildid struct {
		Path string `kong:"required,arg,name='path',help='Paths to extract buildid.',type:'path'"`
	} `cmd:"" help:"Extract buildid."`

	Source struct {
		DebuginfoPath string `kong:"required,arg,name='debuginfo-path',help='Path to debuginfo file',type:'path'"`
		OutPath       string `kong:"arg,name='out-path',help='Path to output archive file',type:'path',default='source.tar.zstd'"`
	} `cmd:"" help:"Build a source archive by discovering files from a given debuginfo file."`
}

func main() {
	flags := flags{}
	kongCtx := kong.Parse(&flags)
	if err := run(kongCtx, flags); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(kongCtx *kong.Context, flags flags) error {
	var g grun.Group
	ctx, cancel := context.WithCancel(context.Background())
	switch kongCtx.Command() {
	case "upload <path>":
		g.Add(func() error {
			conn, err := grpcConn(prometheus.NewRegistry(), flags)
			if err != nil {
				return fmt.Errorf("create gRPC connection: %w", err)
			}
			defer conn.Close()

			debuginfoClient := debuginfopb.NewDebuginfoServiceClient(conn)
			grpcUploadClient := parcadebuginfo.NewGrpcUploadClient(debuginfoClient)

			var (
				buildID string
				reader  io.ReadSeeker
				size    int64
			)

			if !flags.Upload.NoExtract && flags.Upload.Type == "debuginfo" {
				f, err := os.Open(flags.Upload.Path)
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}

				ef, err := elf.NewFile(f)
				if err != nil {
					return fmt.Errorf("open ELF file: %w", err)
				}
				defer ef.Close()

				buildID, err = GetBuildID(ef)
				if err != nil {
					return fmt.Errorf("get Build ID for %q: %w", flags.Upload.Path, err)
				}

				buf := &flexbuf.Buffer{}
				if err := elfwriter.OnlyKeepDebug(buf, f); err != nil {
					return fmt.Errorf("failed to extract debug information: %w", err)
				}

				size = int64(buf.Len())
				buf.SeekStart()
				reader = buf

				if size == 0 {
					return fmt.Errorf("extracted debug information from %q is empty, but must not be empty", flags.Upload.Path)
				}
			} else {
				buildID = flags.Upload.BuildID

				if flags.Upload.Type == "debuginfo" && buildID == "" {
					ef, err := elf.Open(flags.Upload.Path)
					if err != nil {
						return fmt.Errorf("open ELF file: %w", err)
					}
					defer ef.Close()

					buildID, err = GetBuildID(ef)
					if err != nil {
						return fmt.Errorf("get Build ID for %q: %w", flags.Upload.Path, err)
					}
				}

				f, err := os.Open(flags.Upload.Path)
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()

				fi, err := f.Stat()
				if err != nil {
					return fmt.Errorf("stat file: %w", err)
				}

				if fi.Size() == 0 {
					return fmt.Errorf("file %q is empty, but must not be empty", flags.Upload.Path)
				}
				reader = f
				size = fi.Size()
			}

			shouldInitiate, err := debuginfoClient.ShouldInitiateUpload(ctx, &debuginfopb.ShouldInitiateUploadRequest{
				BuildId: buildID,
				Force:   flags.Upload.Force,
				Type:    debuginfoTypeStringToPb(flags.Upload.Type),
			})
			if err != nil {
				return fmt.Errorf("check if upload should be initiated for %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}
			if !shouldInitiate.GetShouldInitiateUpload() {
				fmt.Fprintf(os.Stdout, "Skipping upload of %q with Build ID %q as the store instructed not to: %s\n", flags.Upload.Path, buildID, shouldInitiate.GetReason())
				return nil
			}

			if flags.Upload.NoInitiate {
				fmt.Fprintf(os.Stdout, "Not initiating upload of %q with Build ID %q as requested, but would have requested that next, because: %s\n", flags.Upload.Path, buildID, shouldInitiate.GetReason())
				return nil
			}

			hash, err := hash.Reader(reader)
			if err != nil {
				return fmt.Errorf("calculate hash of %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}

			if _, err := reader.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek to start of %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}

			initiationResp, err := debuginfoClient.InitiateUpload(ctx, &debuginfopb.InitiateUploadRequest{
				BuildId: buildID,
				Hash:    hash,
				Size:    size,
				Force:   flags.Upload.Force,
				Type:    debuginfoTypeStringToPb(flags.Upload.Type),
			})
			if err != nil {
				return fmt.Errorf("initiate upload for %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}

			if flags.LogLevel == LogLevelDebug {
				fmt.Fprintf(os.Stdout, "Upload instructions\nBuildID: %s\nUploadID: %s\nUploadStrategy: %s\nSignedURL: %s\nType: %s\n", initiationResp.GetUploadInstructions().GetBuildId(), initiationResp.GetUploadInstructions().GetUploadId(), initiationResp.GetUploadInstructions().GetUploadStrategy().String(), initiationResp.GetUploadInstructions().GetSignedUrl(), initiationResp.GetUploadInstructions().GetType())
			}

			switch initiationResp.GetUploadInstructions().GetUploadStrategy() {
			case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
				if flags.LogLevel == LogLevelDebug {
					fmt.Fprintf(os.Stdout, "Performing a gRPC upload for %q with Build ID %q.", flags.Upload.Path, buildID)
				}
				_, err = grpcUploadClient.Upload(ctx, initiationResp.GetUploadInstructions(), reader)
			case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
				if flags.LogLevel == LogLevelDebug {
					fmt.Fprintf(os.Stdout, "Performing a signed URL upload for %q with Build ID %q.", flags.Upload.Path, buildID)
				}
				err = uploadViaSignedURL(ctx, initiationResp.GetUploadInstructions().GetSignedUrl(), reader)
			case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_UNSPECIFIED:
				err = errors.New("no upload strategy specified")
			default:
				err = fmt.Errorf("unknown upload strategy: %v", initiationResp.GetUploadInstructions().GetUploadStrategy())
			}
			if err != nil {
				return fmt.Errorf("upload %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}

			_, err = debuginfoClient.MarkUploadFinished(ctx, &debuginfopb.MarkUploadFinishedRequest{
				BuildId:  buildID,
				UploadId: initiationResp.GetUploadInstructions().GetUploadId(),
				Type:     debuginfoTypeStringToPb(flags.Upload.Type),
			})
			if err != nil {
				return fmt.Errorf("mark upload finished for %q with Build ID %q: %w", flags.Upload.Path, buildID, err)
			}

			return nil
		}, func(error) {
			cancel()
		})

	case "extract <path>":
		g.Add(func() error {
			if err := os.RemoveAll(flags.Extract.OutputDir); err != nil {
				return fmt.Errorf("failed to clean output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			if err := os.MkdirAll(flags.Extract.OutputDir, 0o755); err != nil { //nolint:mnd
				return fmt.Errorf("failed to create output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			for _, path := range flags.Extract.Paths {
				ef, err := elf.Open(path)
				if err != nil {
					return fmt.Errorf("open ELF file: %w", err)
				}
				defer ef.Close()

				buildID, err := GetBuildID(ef)
				if err != nil {
					return fmt.Errorf("get Build ID for %q: %w", path, err)
				}

				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()

				// ./out/<buildid>.debuginfo
				output := filepath.Join(flags.Extract.OutputDir, buildID+".debuginfo")

				outFile, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				defer outFile.Close()

				if err := elfwriter.OnlyKeepDebug(outFile, f); err != nil {
					return fmt.Errorf("failed to extract debug information: %w", err)
				}
			}

			return nil
		}, func(error) {
			cancel()
		})

	case "buildid <path>":
		g.Add(func() error {
			ef, err := elf.Open(flags.Buildid.Path)
			if err != nil {
				return fmt.Errorf("open ELF file: %w", err)
			}
			defer ef.Close()

			buildID, err := GetBuildID(ef)
			if err != nil {
				return fmt.Errorf("get Build ID for %q: %w", flags.Buildid.Path, err)
			}

			if buildID == "" {
				return errors.New("failed to extract ELF build ID")
			}

			fmt.Fprintf(os.Stdout, "%s", buildID)
			return nil
		}, func(error) {
			cancel()
		})

	case "source <debuginfo-path>":
		g.Add(func() error {
			f, err := elf.Open(flags.Source.DebuginfoPath)
			if err != nil {
				return fmt.Errorf("open elf: %w", err)
			}
			defer f.Close()

			sf, err := os.Create(flags.Source.OutPath)
			if err != nil {
				return fmt.Errorf("create source archive: %w", err)
			}
			defer sf.Close()

			zw, err := zstd.NewWriter(sf)
			if err != nil {
				return fmt.Errorf("create zstd writer: %w", err)
			}
			defer zw.Close()

			tw := tar.NewWriter(zw)
			defer tw.Close()

			d, err := f.DWARF()
			if err != nil {
				return fmt.Errorf("get dwarf data: %w", err)
			}

			r := d.Reader()
			seen := map[string]struct{}{}
			for {
				e, err := r.Next()
				if err != nil {
					return fmt.Errorf("read DWARF entry: %w", err)
				}
				if e == nil {
					break
				}

				if e.Tag == dwarf.TagCompileUnit {
					lr, err := d.LineReader(e)
					if err != nil {
						return fmt.Errorf("get line reader: %w", err)
					}

					if lr == nil {
						continue
					}

					for _, lineFile := range lr.Files() {
						if lineFile == nil {
							continue
						}
						if _, ok := seen[lineFile.Name]; !ok {
							sourceFile, err := os.Open(lineFile.Name)
							if errors.Is(err, os.ErrNotExist) {
								fmt.Fprintf(os.Stderr, "skipping file %q: does not exist\n", lineFile.Name)
								seen[lineFile.Name] = struct{}{}
								continue
							}
							if err != nil {
								return fmt.Errorf("open file: %w", err)
							}

							stat, err := sourceFile.Stat()
							if err != nil {
								return fmt.Errorf("stat file: %w", err)
							}

							if err := tw.WriteHeader(&tar.Header{
								Name: lineFile.Name,
								Size: stat.Size(),
							}); err != nil {
								return fmt.Errorf("write tar header: %w", err)
							}

							if _, err = io.Copy(tw, sourceFile); err != nil {
								return fmt.Errorf("copy file to tar: %w", err)
							}

							if err := sourceFile.Close(); err != nil {
								return fmt.Errorf("close file: %w", err)
							}

							seen[lineFile.Name] = struct{}{}
						}
					}
				}
			}

			return nil
		}, func(error) {
			cancel()
		})

	default:
		cancel()
		return errors.New("unknown command: " + kongCtx.Command())
	}

	g.Add(grun.SignalHandler(ctx, os.Interrupt, os.Kill))
	return g.Run()
}

func grpcConn(reg prometheus.Registerer, flags flags) (*grpc.ClientConn, error) {
	met := grpc_prometheus.NewClientMetrics()
	met.EnableClientHandlingTimeHistogram()
	reg.MustRegister(met)

	unaryInterceptors := []grpc.UnaryClientInterceptor{
		met.UnaryClientInterceptor(),
	}
	streamInterceptors := []grpc.StreamClientInterceptor{}

	if len(flags.Upload.GRPCHeaders) > 0 {
		unaryInterceptors = append([]grpc.UnaryClientInterceptor{
			customHeadersUnaryInterceptor(flags.Upload.GRPCHeaders)}, unaryInterceptors...)
		streamInterceptors = append([]grpc.StreamClientInterceptor{
			customHeadersStreamInterceptor(flags.Upload.GRPCHeaders)}, streamInterceptors...)
	}

	opts := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
		grpc.WithChainStreamInterceptor(streamInterceptors...),
	}
	if flags.Upload.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			//nolint:gosec
			InsecureSkipVerify: flags.Upload.InsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	if flags.Upload.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    flags.Upload.BearerToken,
			insecure: flags.Upload.Insecure,
		}))
	}

	if flags.Upload.BearerTokenFile != "" {
		b, err := os.ReadFile(flags.Upload.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    string(b),
			insecure: flags.Upload.Insecure,
		}))
	}

	return grpc.NewClient(flags.Upload.StoreAddress, opts...)
}

type perRequestBearerToken struct {
	token    string
	insecure bool
}

func (t *perRequestBearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t *perRequestBearerToken) RequireTransportSecurity() bool {
	return !t.insecure
}

func customHeadersUnaryInterceptor(headers map[string]string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		for key, value := range headers {
			ctx = metadata.AppendToOutgoingContext(ctx, key, value)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func customHeadersStreamInterceptor(headers map[string]string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		for key, value := range headers {
			ctx = metadata.AppendToOutgoingContext(ctx, key, value)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func uploadViaSignedURL(ctx context.Context, url string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func debuginfoTypeStringToPb(s string) debuginfopb.DebuginfoType {
	switch s {
	case "executable":
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_EXECUTABLE
	case "sources":
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_SOURCES
	default:
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED
	}
}

var ErrNoBuildID = errors.New("no build ID")

// GetBuildID extracts the build ID from the provided ELF file. This is read from
// the .note.gnu.build-id or .notes section of the ELF, and may not exist. If no build ID is present
// an ErrNoBuildID is returned.
func GetBuildID(elfFile *elf.File) (string, error) {
	sectionData, err := getSectionData(elfFile, ".note.gnu.build-id")
	if err != nil {
		sectionData, err = getSectionData(elfFile, ".notes")
		if err != nil {
			return "", ErrNoBuildID
		}
	}

	return getBuildIDFromNotes(sectionData)
}

func getSectionData(elfFile *elf.File, sectionName string) ([]byte, error) {
	section := elfFile.Section(sectionName)
	if section == nil {
		return nil, fmt.Errorf("failed to open the %s section", sectionName)
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read data from section %s: %w", sectionName, err)
	}
	return data, nil
}

// getBuildIDFromNotes returns the build ID from an ELF notes section data.
func getBuildIDFromNotes(notes []byte) (string, error) {
	// 0x3 is the "Build ID" type. Not sure where this is standardized.
	buildID, found, err := getNoteHexString(notes, "GNU", 0x3) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("could not determine BuildID: %w", err)
	}
	if !found {
		return "", ErrNoBuildID
	}
	return buildID, nil
}

// getNoteHexString returns the hex string contents of an ELF note from a note section, as described
// in the ELF standard in Figure 2-3.
func getNoteHexString(sectionBytes []byte, name string, noteType uint32) (string, bool, error) {
	// The data stored inside ELF notes is made of one or multiple structs, containing the
	// following fields:
	// 	- namesz	// 32-bit, size of "name"
	// 	- descsz	// 32-bit, size of "desc"
	// 	- type		// 32-bit - 0x3 in case of a BuildID, 0x100 in case of build salt
	// 	- name		// namesz bytes, null terminated
	// 	- desc		// descsz bytes, binary data: the actual contents of the note
	// Because of this structure, the information of the build id starts at the 17th byte.

	// Null terminated string
	nameBytes := append([]byte(name), 0x0) //nolint:mnd
	noteTypeBytes := make([]byte, 4)       //nolint:mnd

	binary.LittleEndian.PutUint32(noteTypeBytes, noteType)
	noteHeader := append(noteTypeBytes, nameBytes...) //nolint:gocritic,makezero

	// Try to find the note in the section
	idx := bytes.Index(sectionBytes, noteHeader)
	if idx == -1 {
		return "", false, nil
	}
	// there needs to be room for descsz
	if idx < 4 { //nolint:mnd
		return "", false, errors.New("could not read note data size")
	}

	idxDataStart := idx + len(noteHeader)
	// data is 32bit-aligned, round up
	idxDataStart += (4 - (idxDataStart & 3)) & 3 //nolint:mnd

	// read descsz and compute the last index of the note data
	dataSize := binary.LittleEndian.Uint32(sectionBytes[idx-4 : idx])
	idxDataEnd := uint64(idxDataStart) + uint64(dataSize) //nolint:gosec

	// Check sanity (64 is totally arbitrary, as we only use it for Linux ID and Build ID)
	if idxDataEnd > uint64(len(sectionBytes)) || dataSize > 64 {
		return "", false, fmt.Errorf(
			"non-sensical note: %d start index: %d, %v end index %d, size %d, section size %d",
			idx, idxDataStart, noteHeader, idxDataEnd, dataSize, len(sectionBytes))
	}
	return hex.EncodeToString(sectionBytes[idxDataStart:idxDataEnd]), true, nil
}
