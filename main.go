package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

func main() {
	listen := flag.String("listen", ":10000", "listen")
	network := flag.String("network", "tcp", "")
	notlsaction := flag.String("notls", "reject", "")
	tlsaction := flag.String("tls", "dunno", "")
	flag.Parse()

	listener, err := net.Listen(*network, *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
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
