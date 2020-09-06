package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func main() {
	listen := flag.String("listen", ":10000", "listen")
	network := flag.String("network", "tcp", "")
	notlsaction := flag.String("notls", "reject", "")
	tlsaction := flag.String("tls", "dunno", "")

	perm := flag.Uint64("perm", 0660, "unix socket permmissions (when -network unix)")
	userU := flag.String("user", "", "unix socket user (when -network unix)")
	groupU := flag.String("group", "", "unix socket group (when -network unix)")
	flag.Parse()

	if *network == "unix" {
		syscall.Umask(0777)
	}

	listener, err := net.Listen(*network, *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if *network == "unix" {
		if err := os.Chmod(*listen, os.FileMode(*perm)); err != nil {
			listener.Close()
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		if *userU != "" {
			userUID, err := user.Lookup(*userU)
			if err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			uid, err := strconv.ParseInt(userUID.Uid, 10, 31)
			if err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			if err := os.Chown(*listen, int(uid), -1); err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}

		if *groupU != "" {
			groupUID, err := user.LookupGroup(*groupU)
			if err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			gid, err := strconv.ParseInt(groupUID.Gid, 10, 31)
			if err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			if err := os.Chown(*listen, -1, int(gid)); err != nil {
				listener.Close()
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}

	}

	wg := sync.WaitGroup{}
	done := make(chan struct{})

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Terminating")
		close(done)
		listener.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			con, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					fmt.Fprintf(os.Stderr, "Accept failed: %v\n", err)
					continue
				}
			}

			wg.Add(1)

			connEnd := make(chan struct{})

			go func() {
				select {
				case <-connEnd:
				case <-done:
					con.Close()
					<-connEnd
				}
				wg.Done()
			}()
			go func() {
				defer func() {
					connEnd <- struct{}{}
				}()
				scanner := bufio.NewScanner(con)
				scanner.Split(bufio.ScanLines)

				var tls string
				for scanner.Scan() {
					s := scanner.Text()
					if strings.HasPrefix(s, "encryption_protocol=") {
						fmt.Sscanf(s, "encryption_protocol=%s", &tls)
					}

					//empty line
					if len(s) == 0 {
						if len(tls) == 0 {
							io.WriteString(con, fmt.Sprintf("action=%v\n\n", *notlsaction))
						} else {
							io.WriteString(con, fmt.Sprintf("action=%v\n\n", *tlsaction))
						}
						tls = ""
					}

				}
				if err := scanner.Err(); err != nil {
					select {
					case <-done:
					default:
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
				}
			}()
		}
	}()

	wg.Wait()
}
