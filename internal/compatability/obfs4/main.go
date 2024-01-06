/*
 * Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Go language Tor Pluggable Transport suite.  Works only as a managed
// client/server.
package main

import (
	"flag"
	"fmt"
	"io"
	golog "log"
	"net"
	"os"
	"path"
	"sync"
	"syscall"

	"github.com/refraction-networking/obfs4/common/drbg"
	"github.com/refraction-networking/obfs4/common/log"
	"github.com/refraction-networking/obfs4/transports"
	"github.com/refraction-networking/obfs4/transports/base"
	"github.com/refraction-networking/obfs4/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

const (
	obfs4proxyVersion = "0.0.9-dev"
	obfs4proxyLogFile = "obfs4proxy.log"
	fwdProxyAddr      = ":9001"
	fwdProxyPort      = 9001
	clientConnectAddr = "127.0.0.1:9001"
)

const (
	nodeIDArg     = "node-id"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"

	publicKeyArg = "public-key"
	iatArg       = "iat-mode"
)

var pubkeyTest = ""
var privkeyTest = ""
var nodeID = ""

var termMon *termMonitor

func clientConn() (net.Conn, error) {

	obfsTransport := obfs4.Transport{}
	args := pt.Args{}

	args.Add(nodeIDArg, nodeID)
	args.Add(publicKeyArg, pubkeyTest)
	args.Add(iatArg, "1")

	c, err := obfsTransport.ClientFactory("")
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory")
	}

	parsedArgs, err := c.ParseArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obfs4 args")
	}

	return c.Dial("tcp", clientConnectAddr, net.Dial, parsedArgs)
}

func useConn(conn net.Conn) error {
	defer conn.Close()

	message := "HELLO WORLD, owo"

	_, err := conn.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if string(buf[:n]) != message {
		golog.Fatalf("unexpected response message: \"%s\"", string(buf[:n]))
	}
	return nil
}

func serverSetup() (launched bool, listeners []net.Listener) {
	name := "obfs4"

	args := pt.Args{}
	args.Add(nodeIDArg, nodeID)
	args.Add(privateKeyArg, privkeyTest)
	seed, err := drbg.NewSeed()
	if err != nil {
		golog.Fatalf("failed to create DRBG seed: %w", err)
		return false, nil
	}
	args.Add(seedArg, seed.Hex())

	t := &obfs4.Transport{}

	f, err := t.ServerFactory("", &args)
	if err != nil {
		golog.Fatalf("failed to create server factory: %w", err)
		return false, nil
	}

	ln, err := net.Listen("tcp", fwdProxyAddr)
	if err != nil {
		return
	}

	go func() {
		_ = serverAcceptLoop(f, ln)
	}()

	log.Infof("%s - registered listener: %s", name, log.ElideAddr(ln.Addr().String()))
	listeners = append(listeners, ln)
	launched = true

	return
}

func serverAcceptLoop(f base.ServerFactory, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); (ok && !e.Timeout()) || !ok {
				return err
			}
			continue
		}
		go serverHandler(f, conn)
	}
}

func serverHandler(f base.ServerFactory, conn net.Conn) {
	defer conn.Close()
	termMon.onHandlerStart()
	defer termMon.onHandlerFinish()

	name := f.Transport().Name()
	addrStr := log.ElideAddr(conn.RemoteAddr().String())
	log.Infof("%s(%s) - new connection", name, addrStr)

	// Instantiate the server transport method and handshake.
	remote, err := f.WrapConn(conn)
	if err != nil {
		log.Warnf("%s(%s) - handshake failed: %s", name, addrStr, log.ElideError(err))
		return
	}

	if err = copyLoop(remote, remote); err != nil {
		log.Warnf("%s(%s) - closed connection: %s", name, addrStr, log.ElideError(err))
	} else {
		log.Infof("%s(%s) - closed connection", name, addrStr)
	}
}

func copyLoop(a net.Conn, b net.Conn) error {
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer b.Close()
		defer a.Close()
		_, err := io.Copy(b, a)
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

func getVersion() string {
	return fmt.Sprintf("obfs4proxy-%s", obfs4proxyVersion)
}

// Feature #15435 adds a new env var for determining if Tor keeps stdin
// open for use in termination detection.
func ptShouldExitOnStdinClose() bool {
	return os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1"
}

func main() {
	// Initialize the termination state monitor as soon as possible.
	termMon = newTermMonitor()

	// Handle the command line arguments.
	_, execName := path.Split(os.Args[0])
	showVer := flag.Bool("version", false, "Print version and exit")
	logLevelStr := flag.String("logLevel", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")
	isClient := flag.Bool("client", false, "set this if client")
	flag.Parse()

	if *showVer {
		fmt.Printf("%s\n", getVersion())
		os.Exit(0)
	}
	if err := log.SetLogLevel(*logLevelStr); err != nil {
		golog.Fatalf("[ERROR]: %s - failed to set log level: %s", execName, err)
	}

	// Determine if this is a client or server, initialize the common state.
	var ptListeners []net.Listener
	var launched bool
	var err error
	if err = transports.Init(); err != nil {
		log.Errorf("%s - failed to initialize transports: %s", execName, err)
		os.Exit(-1)
	}

	log.Noticef("%s - launched", getVersion())

	// Do the managed pluggable transport protocol configuration.
	if *isClient {
		log.Infof("%s - initializing client transport listeners", execName)
		conn, err := clientConn()
		if err != nil {
			golog.Fatalf("failed to dial and wrap")
		}
		go useConn(conn)
	} else {
		log.Infof("%s - initializing server transport listeners", execName)
		launched, ptListeners = serverSetup()
	}
	if !launched {
		// Initialization failed, the client or server setup routines should
		// have logged, so just exit here.
		os.Exit(-1)
	}

	log.Infof("%s - accepting connections", execName)
	defer func() {
		log.Noticef("%s - terminated", execName)
	}()

	// At this point, the pt config protocol is finished, and incoming
	// connections will be processed.  Wait till the parent dies
	// (immediate exit), a SIGTERM is received (immediate exit),
	// or a SIGINT is received.
	if sig := termMon.wait(false); sig == syscall.SIGTERM {
		return
	}

	// Ok, it was the first SIGINT, close all listeners, and wait till,
	// the parent dies, all the current connections are closed, or either
	// a SIGINT/SIGTERM is received, and exit.
	for _, ln := range ptListeners {
		ln.Close()
	}
	termMon.wait(true)
}
