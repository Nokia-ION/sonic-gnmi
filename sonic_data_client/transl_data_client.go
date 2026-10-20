// Package client provides a generic access layer for data available in system
package client

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	pathutil "github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/Workiva/go-datastructures/queue"
	log "github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	gnmi_extpb "github.com/openconfig/gnmi/proto/gnmi_ext"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-gnmi/common_utils"
	spb "github.com/sonic-net/sonic-gnmi/proto"
	transutil "github.com/sonic-net/sonic-gnmi/transl_utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DELETE     int = 0
	REPLACE    int = 1
	UPDATE     int = 2
	maxWorkers     = 2 // max workers for parallel processing of Get/Subscribe requests
)

var useParallelProcessing = flag.Bool("use_parallel_processing", false, "use parallel processing for GET/SUBSCRIBE requests")
var translProcessGetFunc = transutil.TranslProcessGet
var isSubscribeSupportedFunc = translib.IsSubscribeSupported
var translibSubscribeFunc = translib.Subscribe

type TranslClient struct {
	prefix *gnmipb.Path
	/* GNMI Path to REST URL Mapping */
	path2URI map[*gnmipb.Path]string
	channel  chan struct{}
	q        *queue.PriorityQueue
	superSub *superSubscription

	synced     sync.WaitGroup  // Control when to send gNMI sync_response
	w          *sync.WaitGroup // wait for all sub go routines to finish
	mu         sync.RWMutex    // Mutex for data protection among routines for transl_client
	ctx        context.Context //Contains Auth info and request info
	wakeChan   chan bool       // wakeChan is used to wake up the client to notify it is the new primary client.
	extensions []*gnmi_extpb.Extension

	version  *translib.Version // Client version; populated by parseVersion()
	encoding gnmipb.Encoding
}
type pathFromGetReq struct {
	path *gnmipb.Path
	uri  string
	c    *TranslClient
}

type pathFromSubReq struct {
	path string
	ts   *translSubscriber
}

func findMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func joinErrorsWithNewline(errs []error) error {
	//Length of 'err' validation is done before func call.
	var errStrings []string
	for _, err := range errs {
		if err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}
	if len(errStrings) == 0 {
		return nil // Return actual nil, not an empty error object
	}
	// Using "\n" matches the visual output of errors.Join
	return fmt.Errorf("%s", strings.Join(errStrings, "\n"))
}

func NewTranslClient(prefix *gnmipb.Path, getpaths []*gnmipb.Path, ctx context.Context, extensions []*gnmi_extpb.Extension, opts ...TranslClientOption) (Client, error) {
	var client TranslClient
	var err error
	client.ctx = ctx
	client.prefix = prefix
	client.extensions = extensions
	for _, o := range opts {
		if e, ok := o.(TranslEncodingOption); ok {
			client.encoding = e.Encoding
		}
	}

	if getpaths != nil {
		var addWildcardKeys bool
		for _, o := range opts {
			if _, ok := o.(TranslWildcardOption); ok {
				addWildcardKeys = true
			}
		}

		client.path2URI = make(map[*gnmipb.Path]string)
		/* Populate GNMI path to REST URL map. */
		err = transutil.PopulateClientPaths(prefix, getpaths, &client.path2URI, addWildcardKeys)
	}
	client.wakeChan = make(chan bool, 1)

	if err != nil {
		return nil, err
	} else {
		return &client, nil
	}
}

func (c *TranslClient) Get(w *sync.WaitGroup) ([]*spb.Value, error) {
	rc, ctx := common_utils.GetContext(c.ctx)
	c.ctx = ctx
	var errs []error
	var values []*spb.Value
	ts := time.Now()

	version := getBundleVersion(c.extensions)
	if version != nil {
		rc.BundleVersion = version
	}
	// Iterate through all GNMI paths in parallel. The max number of workers is equal to
	// the number of Openconfig modules in a root query.
	numPaths := len(c.path2URI)
	pathChan := make(chan pathFromGetReq, numPaths)
	valueChan := make(chan *spb.Value, numPaths)
	errChan := make(chan error, numPaths)
	workerWg := &sync.WaitGroup{}
	readerWg := &sync.WaitGroup{}

	numWorkers := 1
	if *useParallelProcessing {
		numWorkers = findMin(numPaths, maxWorkers)
	}

	// Spawn workers to process the paths in the GET request.
	for i := 0; i < numWorkers; i++ {
		workerWg.Add(1)
		go processGetWorker(pathChan, valueChan, errChan, workerWg)
	}

	// Send the paths in the GET request to the workers through the channel.
	for gnmiPath, URIPath := range c.path2URI {
		pathChan <- pathFromGetReq{path: gnmiPath, uri: URIPath, c: c}
	}
	close(pathChan)

	// Start goroutines to read the response values and errors from the workers.
	readerWg.Add(2)
	go func() {
		defer readerWg.Done()
		for value := range valueChan {
			values = append(values, value)
		}
	}()
	go func() {
		defer readerWg.Done()
		for err := range errChan {
			errs = append(errs, err)
		}
	}()

	// Wait for all goroutines to finish.
	workerWg.Wait()
	close(valueChan)
	close(errChan)
	readerWg.Wait()

	if len(errs) != 0 {
		return nil, joinErrorsWithNewline(errs)
	}

	/* The values structure at the end is returned and then updates in notitications as
	specified in the proto file in the server.go */

	log.V(6).Infof("TranslClient : Getting #%v", values)
	log.V(4).Infof("TranslClient :Get done, total time taken: %v ms", int64(time.Since(ts)/time.Millisecond))

	return values, nil
}

// processGetWorker is a worker function to remove paths from a GET request off of the channel and process them.
func processGetWorker(pathChan <-chan pathFromGetReq, valueChan chan<- *spb.Value, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range pathChan {
		log.Infof("getWorker processing path: %v", path)
		val, resp, err := translProcessGetFunc(path.uri, nil, path.c.ctx, path.c.encoding)
		if err != nil {
			errChan <- err
			return
		}

		var valueTree ygot.ValidatedGoStruct
		respPath := path.path
		if resp != nil {
			valueTree = resp.ValueTree
			// An expansion that matched no instance still answers the request:
			// the list stood in for a node none of its instances carry, so the
			// answer is no updates rather than the list itself.
			instances, expanded := expandListFallback(path.c.prefix, path.path, path.c.encoding, resp, val)
			if !expanded {
				instances, expanded = expandWildcardListTarget(path.c.prefix, path.path, path.c.encoding, val)
			}
			if expanded {
				for _, v := range instances {
					valueChan <- v
				}
				continue
			}
			if p, ok := servedRequestPath(path.c.prefix, path.path, resp.ServedPath); ok {
				respPath = p
			}
		}
		v, err := buildValueForGet(path.c.prefix, respPath, path.c.encoding, val, valueTree)
		if err != nil {
			errChan <- err
			return
		}
		// A list that stood in for the request carries every instance whole,
		// so PROTO keeps only the leaves under the path asked for. As with
		// JSON, an answer left with nothing is no update at all.
		if n := v.GetNotification(); n != nil && len(n.GetUpdate()) != 0 {
			n.Update = updatesUnderPath(path.c.prefix, path.path, n)
			if len(n.Update) == 0 && respPath != path.path {
				continue
			}
		}

		valueChan <- v
	}
}

// updatesUnderPath returns the updates of n that sit at or below the request
// path. A wildcarded or unkeyed list in the request matches every instance.
func updatesUnderPath(prefix, path *gnmipb.Path, n *gnmipb.Notification) []*gnmipb.Update {
	want := append(append([]*gnmipb.PathElem{}, prefix.GetElem()...), path.GetElem()...)
	kept := n.Update[:0]
	for _, u := range n.Update {
		got := append(append([]*gnmipb.PathElem{}, n.GetPrefix().GetElem()...), u.GetPath().GetElem()...)
		if pathElemsCover(want, got) {
			kept = append(kept, u)
		}
	}
	return kept
}

// pathElemsCover reports whether got is want or a node below it.
func pathElemsCover(want, got []*gnmipb.PathElem) bool {
	if len(got) < len(want) {
		return false
	}
	for i, w := range want {
		g := got[i]
		if unprefixed(w.GetName()) != unprefixed(g.GetName()) {
			return false
		}
		for k, wv := range w.GetKey() {
			if wv == "*" {
				continue
			}
			gv, ok := g.GetKey()[k]
			if !ok || (gv != wv && gv != unprefixed(wv)) {
				return false
			}
		}
	}
	return true
}

func (c *TranslClient) Set(delete []*gnmipb.Path, replace []*gnmipb.Update, update []*gnmipb.Update) error {
	rc, ctx := common_utils.GetContext(c.ctx)
	c.ctx = ctx
	version := getBundleVersion(c.extensions)
	if version != nil {
		rc.BundleVersion = version
	}

	if (len(delete) + len(replace) + len(update)) > 1 {
		return transutil.TranslProcessBulk(delete, replace, update, c.prefix, c.ctx)
	} else {
		if len(delete) == 1 {
			return transutil.TranslProcessDelete(c.prefix, delete[0], c.ctx)
		}
		if len(replace) == 1 {
			return transutil.TranslProcessReplace(c.prefix, replace[0], c.ctx)
		}
		if len(update) == 1 {
			return transutil.TranslProcessUpdate(c.prefix, update[0], c.ctx)
		}
	}
	return nil
}

func enqueFatalMsgTranslib(c *TranslClient, msg string) {
	c.q.Put(Value{
		&spb.Value{
			Timestamp: time.Now().UnixNano(),
			Fatal:     msg,
		},
	})
}

func enqueueSyncMessage(c *TranslClient) {
	m := &spb.Value{
		Timestamp:    time.Now().UnixNano(),
		SyncResponse: true,
	}
	c.q.Put(Value{m})
}

// recoverSubscribe recovers from possible panics during subscribe handling.
// It pushes a fatal message to the RPC handler's queue, which forces the server to
// close the RPC with an error status. Should always be used as a deferred function.
func recoverSubscribe(c *TranslClient) {
	if r := recover(); r != nil {
		buff := make([]byte, 1<<12)
		buff = buff[:runtime.Stack(buff, false)]
		log.Error(string(buff))

		err := status.Errorf(codes.Internal, "%v", r)
		enqueFatalMsgTranslib(c, fmt.Sprintf("Subscribe operation failed with error =%v", err.Error()))
	}
}

type ticker_info struct {
	t         *time.Ticker
	sub       *gnmipb.Subscription
	interval  int
	pathStr   string
	heartbeat bool
}

func getTranslNotificationType(mode gnmipb.SubscriptionMode) translib.NotificationType {
	switch mode {
	case gnmipb.SubscriptionMode_ON_CHANGE:
		return translib.OnChange
	case gnmipb.SubscriptionMode_SAMPLE:
		return translib.Sample
	default:
		return translib.TargetDefined
	}
}

func tickerCleanup(tickers map[int]*time.Ticker) {
	for _, ticker := range tickers {
		ticker.Stop()
	}
}

func (c *TranslClient) StreamRun(q *queue.PriorityQueue, stop chan struct{}, w *sync.WaitGroup, subscribe *gnmipb.SubscriptionList) {
	c.w = w

	defer c.w.Done()
	defer recoverSubscribe(c)

	c.q = q
	c.channel = stop
	c.encoding = subscribe.Encoding

	if err := c.parseVersion(); err != nil {
		enqueFatalMsgTranslib(c, err.Error())
		return
	}
	intervalToTickerInfoMap := make(map[int][]*ticker_info)

	var subscribe_mode gnmipb.SubscriptionMode
	translPaths := make([]translib.IsSubscribePath, len(subscribe.Subscription))
	sampleCache := make(map[string]*ygotCache)

	for i, sub := range subscribe.Subscription {
		uri, ok := c.path2URI[sub.Path]
		if !ok {
			// A whole tree path is served as the union of its top level
			// subtrees, which a STREAM subscription cannot express yet.
			enqueFatalMsgTranslib(c, fmt.Sprintf(
				"Subscribe operation failed with error = whole tree path %q is supported only in ONCE and POLL modes",
				sub.Path))
			return
		}
		translPaths[i].ID = uint32(i)
		translPaths[i].Path = uri
		translPaths[i].Mode = getTranslNotificationType(sub.Mode)
	}

	rc, _ := common_utils.GetContext(c.ctx)
	ss := translib.NewSubscribeSession()
	defer ss.Close()

	req := translib.IsSubscribeRequest{
		Paths:   translPaths,
		Session: ss,
		User:    translib.UserRoles{Name: rc.Auth.User, Roles: rc.Auth.Roles},
	}
	if c.version != nil {
		req.ClientVersion = *c.version
	}

	subSupport, err := isSubscribeSupportedFunc(req)
	if err != nil {
		enqueFatalMsgTranslib(c, fmt.Sprintf("Subscribe operation failed with error =%v", err.Error()))
		return
	}

	numSubWorkers := 1
	if *useParallelProcessing {
		numSubWorkers = findMin(len(subscribe.Subscription), maxWorkers)
	}

	var onChangeSubsString []string
	// Spawn routines to process the Sample subscriptions
	wg := &sync.WaitGroup{}
	subChan := make(chan pathFromSubReq, len(subscribe.Subscription))
	for i := 0; i < numSubWorkers; i++ {
		wg.Add(1)
		go processSubWorker(subChan, wg)
	}

	for i, pInfo := range subSupport {
		sub := subscribe.Subscription[pInfo.ID]
		log.V(6).Infof("Start Sub: %v", sub)
		pathStr := pInfo.Path

		switch sub.Mode {
		case gnmipb.SubscriptionMode_TARGET_DEFINED:
			if pInfo.IsOnChangeSupported && pInfo.PreferredType == translib.OnChange {
				subscribe_mode = gnmipb.SubscriptionMode_ON_CHANGE
			} else {
				subscribe_mode = gnmipb.SubscriptionMode_SAMPLE
			}
		case gnmipb.SubscriptionMode_ON_CHANGE:
			if pInfo.IsOnChangeSupported {
				subscribe_mode = gnmipb.SubscriptionMode_ON_CHANGE
			} else {
				enqueFatalMsgTranslib(c, fmt.Sprintf("ON_CHANGE Streaming mode invalid for %v", pathStr))
				close(subChan)
				return
			}
		case gnmipb.SubscriptionMode_SAMPLE:
			subscribe_mode = gnmipb.SubscriptionMode_SAMPLE
		default:
			enqueFatalMsgTranslib(c, fmt.Sprintf("Invalid Subscription Mode %d", sub.Mode))
			close(subChan)
			return
		}

		if pInfo.MinInterval <= 0 { // should not happen
			pInfo.MinInterval = translib.MinSubscribeInterval
		}

		if hb := sub.HeartbeatInterval; hb > 0 && hb < uint64(pInfo.MinInterval)*uint64(time.Second) {
			enqueFatalMsgTranslib(c, fmt.Sprintf("Invalid Heartbeat Interval %ds, minimum interval is %ds",
				sub.HeartbeatInterval/uint64(time.Second), subSupport[i].MinInterval))
			close(subChan)
			return
		}

		log.V(6).Infof("subscribe_mode %v for path %s", subscribe_mode, pathStr)
		if subscribe_mode == gnmipb.SubscriptionMode_SAMPLE {
			interval := int(sub.SampleInterval)
			minInterval := pInfo.MinInterval * int(time.Second)
			if interval == 0 {
				interval = minInterval
			} else if interval < minInterval {
				enqueFatalMsgTranslib(c, fmt.Sprintf("Invalid SampleInterval %ds, minimum interval is %ds", interval/int(time.Second), pInfo.MinInterval))
				close(subChan)
				return
			}

			reqPath, _ := ygot.StringToStructuredPath(pathStr)
			yCache := newYgotCache(reqPath)
			sampleCache[pathStr] = yCache
			ts := translSubscriber{
				client:      c,
				session:     ss,
				sampleCache: yCache,
				filterMsgs:  subscribe.UpdatesOnly,
			}

			// Force ignore init updates for subpaths to prevent duplicates.
			// But performs duplicate gets though -- needs optimization.
			if pInfo.IsSubPath {
				ts.filterMsgs = true
			}

			// do initial sync & build the cache
			// Add the path to the channel to be processed in parallel
			subChan <- pathFromSubReq{path: pathStr, ts: &ts}

			addTimer(intervalToTickerInfoMap, interval, sub, pathStr, false)
			//Heartbeat intervals are valid for SAMPLE in the case suppress_redundant is specified
			if sub.SuppressRedundant && sub.HeartbeatInterval > 0 {
				addTimer(intervalToTickerInfoMap, int(sub.HeartbeatInterval), sub, pathStr, true)
			}
		} else if subscribe_mode == gnmipb.SubscriptionMode_ON_CHANGE {
			onChangeSubsString = append(onChangeSubsString, pathStr)
			if sub.HeartbeatInterval > 0 {
				addTimer(intervalToTickerInfoMap, int(sub.HeartbeatInterval), sub, pathStr, true)
			}
		}
		log.V(6).Infof("End Sub: %v", sub)
	}
	close(subChan)

	if len(onChangeSubsString) > 0 {
		ts := translSubscriber{
			client:     c,
			session:    ss,
			filterMsgs: subscribe.UpdatesOnly,
			sampleWg:   wg,
		}
		onChangeQ := ts.doOnChange(onChangeSubsString)
		defer onChangeQ.Dispose()
	} else {
		// If at least one ON_CHANGE subscription was present, then
		// ts.doOnChange() would have sent the sync message.
		// Explicitly send one here if all are SAMPLE subscriptions.
		wg.Wait()
		enqueueSyncMessage(c)
	}

	// Add the subscription to a SuperSubscrption.
	c.addClientToSuperSubscription(subscribe)
	defer c.leaveSuperSubscription()

	// Get tickers and cases to do samples.
	err = c.superSub.populateTickers(intervalToTickerInfoMap)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to fetch shared tickers from Super Subscription: %v", err)
		log.V(0).Info(errMsg)
		enqueFatalMsgTranslib(c, errMsg)
		return
	}
	cases, caseIndexToIntervalMap := buildSelectCases(intervalToTickerInfoMap, c.channel)

	// Non-primary clients do not need to listen for ticks unless they're woken up by the Super Subscription.
	for !c.isPrimary() {
		select {
		case <-c.wakeChan:
			log.V(2).Infof("Secondary client (%p) waking up: isPrimary=%v, tickers=%v", c, c.isPrimary(), intervalToTickerInfoMap)
			continue
		case <-c.channel:
			log.V(2).Infof("Secondary client (%p) received close signal", c)
			return
		}
	}

	for {
		chosen, _, ok := reflect.Select(cases)
		if !ok || chosen >= len(caseIndexToIntervalMap) || c.q == nil || c.q.Disposed() {
			log.V(2).Infof("TranslClient (%p) exiting StreamRun because an exit signal was received!", c)
			return
		}

		// Start goroutines to process the Sample.
		ticks := intervalToTickerInfoMap[caseIndexToIntervalMap[chosen]]
		tickSubChan := make(chan pathFromSubReq, len(ticks))
		numTickWorkers := 1
		if *useParallelProcessing {
			numTickWorkers = findMin(len(ticks), maxWorkers)
		}
		for i := 0; i < numTickWorkers; i++ {
			wg.Add(1)
			go processSubWorker(tickSubChan, wg)
		}
		for _, tick := range ticks {
			log.V(6).Infof("tick, heartbeat: %t, path: %s\n", tick.heartbeat, c.path2URI[tick.sub.Path])
			ts := translSubscriber{
				client:      c,
				session:     ss,
				sampleCache: sampleCache[tick.pathStr],
				filterDups:  (!tick.heartbeat && tick.sub.SuppressRedundant),
				sampleWg:    wg,
			}
			tickSubChan <- pathFromSubReq{path: tick.pathStr, ts: &ts}
		}
		close(tickSubChan)
		wg.Wait()
	}
}

func processSubWorker(subChan <-chan pathFromSubReq, wg *sync.WaitGroup) {
	defer wg.Done()
	for sub := range subChan {
		sub.ts.doSample(sub.path)
	}
}

// addTimer adds a new ticker_info with the given interval, sub, and heartbeat to the intervalToTickerInfoMap.
func addTimer(intervalToTickerInfoMap map[int][]*ticker_info, interval int, sub *gnmipb.Subscription, pathStr string, heartbeat bool) {
	if tickers, ok := intervalToTickerInfoMap[interval]; ok && tickers != nil {
		tickers = append(tickers, &ticker_info{
			sub:       sub,
			pathStr:   pathStr,
			interval:  interval,
			heartbeat: heartbeat,
		})
		intervalToTickerInfoMap[interval] = tickers
	} else {
		intervalToTickerInfoMap[interval] = []*ticker_info{{
			sub:       sub,
			pathStr:   pathStr,
			interval:  interval,
			heartbeat: heartbeat,
		}}
	}
}

// buildSelectCases takes in the intervalToTickerInfoMap and a close channel and returns the cases and caseIndexToIntervalMap that include
// those ticker channels.
// - cases is a slice of SelectCase used to call select across all the ticker and close channels.
// - caseIndexToIntervalMap is a map from ticker index within the cases slice to the corresponding interval. It can be used to
// associate an interval with the chosen case during the select operation.
func buildSelectCases(intervalToTickerInfoMap map[int][]*ticker_info, closeChan <-chan struct{}) ([]reflect.SelectCase, map[int]int) {
	cases := make([]reflect.SelectCase, 0)
	caseIndexToIntervalMap := make(map[int]int)

	for interval, tickers := range intervalToTickerInfoMap {
		if len(tickers) < 1 {
			continue
		}
		ticker := tickers[0]
		if ticker == nil {
			log.V(0).Infof("Failed to build select case for interval %v because ticker is nil!", interval)
			continue
		}
		caseIndexToIntervalMap[len(cases)] = interval
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ticker.t.C)})
	}
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(closeChan)})
	return cases, caseIndexToIntervalMap
}

func (c *TranslClient) PollRun(q *queue.PriorityQueue, poll chan struct{}, w *sync.WaitGroup, subscribe *gnmipb.SubscriptionList) {
	c.w = w
	defer c.w.Done()
	defer recoverSubscribe(c)
	c.q = q
	c.channel = poll
	c.encoding = subscribe.Encoding

	if err := c.parseVersion(); err != nil {
		enqueFatalMsgTranslib(c, err.Error())
		return
	}

	synced := false
	for {
		_, more := <-c.channel
		if !more {
			log.V(1).Infof("%v poll channel closed, exiting pollDb routine", c)
			enqueFatalMsgTranslib(c, "")
			return
		}

		t1 := time.Now()
		// Spawn worker threads to process the subscription
		numPaths := len(c.path2URI)
		wg := &sync.WaitGroup{}
		subChan := make(chan pathFromSubReq, numPaths)
		numWorkers := 1
		if *useParallelProcessing {
			numWorkers = findMin(numPaths, maxWorkers)
		}
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go processSubWorker(subChan, wg)
		}
		for _, gnmiPath := range c.path2URI {
			if synced || !subscribe.UpdatesOnly {
				ts := translSubscriber{client: c}
				subChan <- pathFromSubReq{path: gnmiPath, ts: &ts}
			}
		}
		close(subChan)
		wg.Wait()

		enqueueSyncMessage(c)
		synced = true
		log.V(4).Infof("Sync done, poll time taken: %v ms", int64(time.Since(t1)/time.Millisecond))
	}
}

func (c *TranslClient) OnceRun(q *queue.PriorityQueue, once chan struct{}, w *sync.WaitGroup, subscribe *gnmipb.SubscriptionList) {
	c.w = w
	defer c.w.Done()
	defer recoverSubscribe(c)

	c.q = q
	c.channel = once
	c.encoding = subscribe.Encoding

	if err := c.parseVersion(); err != nil {
		enqueFatalMsgTranslib(c, err.Error())
		return
	}

	_, more := <-c.channel
	if !more {
		log.V(1).Infof("%v once channel closed, exiting onceDb routine", c)
		enqueFatalMsgTranslib(c, "")
		return
	}

	t1 := time.Now()
	// Spawn worker threads to process the subscription
	numPaths := len(c.path2URI)
	wg := &sync.WaitGroup{}
	subChan := make(chan pathFromSubReq, numPaths)
	numWorkers := 1
	if *useParallelProcessing {
		numWorkers = findMin(numPaths, maxWorkers)
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go processSubWorker(subChan, wg)
	}
	for _, gnmiPath := range c.path2URI {
		ts := translSubscriber{client: c}
		subChan <- pathFromSubReq{path: gnmiPath, ts: &ts}
	}
	close(subChan)
	wg.Wait()
	enqueueSyncMessage(c)
	log.V(4).Infof("Sync done, once time taken: %v ms", int64(time.Since(t1)/time.Millisecond))

}

func (c *TranslClient) Capabilities() []gnmipb.ModelData {
	rc, ctx := common_utils.GetContext(c.ctx)
	c.ctx = ctx
	version := getBundleVersion(c.extensions)
	if version != nil {
		rc.BundleVersion = version
	}
	/* Fetch the supported models. */
	supportedModels := transutil.GetModels()
	return supportedModels
}

func (c *TranslClient) Close() error {
	return nil
}
func (c *TranslClient) SentOne(val *Value) {
}

func (c *TranslClient) FailedSend() {
}

func getBundleVersion(extensions []*gnmi_extpb.Extension) *string {
	for _, e := range extensions {
		switch v := e.Ext.(type) {
		case *gnmi_extpb.Extension_RegisteredExt:
			if v.RegisteredExt.Id == spb.BUNDLE_VERSION_EXT {
				var bv spb.BundleVersion
				proto.Unmarshal(v.RegisteredExt.Msg, &bv)
				return &bv.Version
			}

		}
	}
	return nil
}

// stripOCModulePrefix removes YANG module prefixes from path elements when the
// request origin is "openconfig". ygnmi/ygot resolve schema nodes by unqualified
// names (e.g. "interfaces") once origin is set.
func stripOCModulePrefix(origin string, p *gnmipb.Path) {
	if p == nil || origin != "openconfig" {
		return
	}
	pathutil.RemoveModulePrefix(p)
}

// resolveStripOrigin returns "openconfig" when the prefix or path carries that
// origin, matching subscribe behaviour (see client_subscribe.go and
// translSubscriber.stripOCModulePrefix).
func resolveStripOrigin(prefix, path *gnmipb.Path) string {
	origin := ""
	if prefix != nil {
		origin = prefix.GetOrigin()
	}
	if origin == "" && path != nil {
		origin = path.GetOrigin()
	}
	if origin == "openconfig" {
		return "openconfig"
	}
	return ""
}

// resolveGetStripOrigin returns the origin used to decide GET response path
// stripping. Uses the same openconfig check as subscribe, and treats unprefixed
// OpenConfig paths (/interfaces/...) as openconfig because TranslClient is
// OpenConfig-only and those requests do not set Path.Origin on the gNMI message.
func resolveGetStripOrigin(prefix, path *gnmipb.Path) string {
	if o := resolveStripOrigin(prefix, path); o != "" {
		return o
	}
	return "openconfig"
}

// responsePath returns a copy of path with module prefixes stripped when origin
// is openconfig. The input path is left unchanged so internal path2URI keys are
// stable.
// servedRequestPath re-expresses the path translib actually served as a
// request path, so that an update describes the payload it carries rather than
// the path that was asked for. translib only ever falls back to a prefix of
// the requested path, so the answer is the request path cut to the served
// depth, which leaves the client's prefix untouched.
//
// Reports false when there is nothing to re-express, or when the served path
// cannot be lined up with the request, in which case the caller keeps the
// path it already had.
func servedRequestPath(prefix, path *gnmipb.Path, servedPath string) (*gnmipb.Path, bool) {
	if servedPath == "" {
		return nil, false
	}
	// Only the Elem form can be cut by depth; GnmiTranslFullPath still accepts
	// the deprecated Element form, which carries no keys to count against.
	if path.GetElem() == nil {
		return nil, false
	}
	served, err := ygot.StringToPath(servedPath, ygot.StructuredPath)
	if err != nil {
		log.V(1).Infof("cannot parse served path %q: %v", servedPath, err)
		return nil, false
	}
	depth := len(served.GetElem()) - len(prefix.GetElem())
	if depth < 0 || depth > len(path.GetElem()) {
		log.V(1).Infof("served path %q does not sit under prefix %v", servedPath, prefix)
		return nil, false
	}
	shortened := proto.Clone(path).(*gnmipb.Path)
	shortened.Elem = shortened.GetElem()[:depth]
	return shortened, true
}

// expandListFallback splits a list payload that translib served in place of a
// node below it into one update per list instance, each addressed by its keys.
//
// An unkeyed or wildcarded list in a request asks about every instance, so the
// answer is one update per instance. A single update carrying the whole list
// names no instance, and a client that resolves its request path against the
// response path, as the ygot based ones do, cannot read the node it asked for
// out of that.
//
// Returns nil when the payload cannot be split this way, which leaves the
// caller to label one update with the list path.
func expandListFallback(prefix, path *gnmipb.Path, enc gnmipb.Encoding,
	resp *translib.GetResponse, typedVal *gnmipb.TypedValue) ([]*spb.Value, bool) {

	if resp == nil || resp.ServedPath == "" || typedVal == nil {
		return nil, false
	}
	// PROTO builds its updates by walking the value tree instead.
	if enc != gnmipb.Encoding_JSON && enc != gnmipb.Encoding_JSON_IETF {
		return nil, false
	}

	listPath, ok := servedRequestPath(prefix, path, resp.ServedPath)
	if !ok {
		return nil, false
	}
	depth := len(listPath.GetElem())
	// Nothing was cut, so there is no list standing in for the request.
	if depth == 0 || depth >= len(path.GetElem()) {
		return nil, false
	}
	listElem := path.GetElem()[depth-1]
	remainder := path.GetElem()[depth:]

	// translib names the keys from the schema. A request that wildcarded the
	// list rather than leaving it bare also carries them.
	keyNames := resp.ServedListKeys
	if len(keyNames) == 0 {
		for name := range listElem.GetKey() {
			keyNames = append(keyNames, name)
		}
	}
	if len(keyNames) == 0 {
		return nil, false
	}

	return expandListInstances(prefix, path, enc, depth, keyNames, remainder, typedVal)
}

// expandWildcardListTarget splits the payload of a request that ends at a list
// with every key wildcarded into one update per instance, each addressed by its
// keys. translib serves such a request as the keyless list, which it answers
// as one array; a "*" means each instance, and an update path cannot carry a
// wildcard, so the array is split here.
//
// A bare list at the end of the path is left as one array, which is what the
// translib client has always returned for it.
func expandWildcardListTarget(prefix, path *gnmipb.Path, enc gnmipb.Encoding,
	typedVal *gnmipb.TypedValue) ([]*spb.Value, bool) {

	if typedVal == nil {
		return nil, false
	}
	if enc != gnmipb.Encoding_JSON && enc != gnmipb.Encoding_JSON_IETF {
		return nil, false
	}
	elems := path.GetElem()
	if len(elems) == 0 {
		return nil, false
	}
	last := elems[len(elems)-1]
	if len(last.GetKey()) == 0 {
		return nil, false
	}
	keyNames := make([]string, 0, len(last.GetKey()))
	for name, value := range last.GetKey() {
		if value != "*" {
			return nil, false
		}
		keyNames = append(keyNames, name)
	}

	return expandListInstances(prefix, path, enc, len(elems), keyNames, nil, typedVal)
}

// expandListInstances turns the list payload for the list at path element
// depth-1 into one update per instance, carrying the node remainder names
// below each instance, or the instance itself when remainder is empty.
// Instances that do not carry that node are left out.
func expandListInstances(prefix, path *gnmipb.Path, enc gnmipb.Encoding, depth int,
	keyNames []string, remainder []*gnmipb.PathElem, typedVal *gnmipb.TypedValue) ([]*spb.Value, bool) {

	listElem := path.GetElem()[depth-1]
	entries, ok := listEntriesFromPayload(typedVal, unprefixed(listElem.GetName()))
	if !ok {
		return nil, false
	}

	identityKeys := identityrefKeys(path.GetElem()[:depth], keyNames)

	values := make([]*spb.Value, 0, len(entries))
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil {
			return nil, false
		}

		keys := make(map[string]string, len(keyNames))
		for _, name := range keyNames {
			raw, found := jsonField(fields, name)
			if !found {
				return nil, false
			}
			key, ok := jsonScalarString(raw)
			if !ok {
				return nil, false
			}
			// RFC 7951 qualifies an identity with its module, a path key
			// does not.
			if identityKeys[name] {
				if i := strings.IndexByte(key, ':'); i >= 0 {
					key = key[i+1:]
				}
			}
			keys[name] = key
		}

		node := json.RawMessage(entry)
		if len(remainder) != 0 {
			var found bool
			if node, found = jsonNodeAt(fields, remainder); !found {
				continue
			}
		}

		instance := proto.Clone(path).(*gnmipb.Path)
		instance.Elem[depth-1] = &gnmipb.PathElem{Name: listElem.GetName(), Key: keys}
		v, err := buildValue(prefix, instance, enc,
			&gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: node}}, nil)
		if err != nil || v == nil {
			log.V(1).Infof("cannot build update for list instance %v: %v", keys, err)
			return nil, false
		}
		values = append(values, v)
	}

	return values, true
}

// identityrefKeys reports which of keyNames are identityref keys of the list
// that elems name, directly or through a leafref to a sibling leaf such as
// acl-set's type, which points at config/type. Their RFC 7951 values carry a
// module prefix; a key cannot be told apart from an IPv6 address by its text,
// so the schema decides.
func identityrefKeys(elems []*gnmipb.PathElem, keyNames []string) map[string]bool {
	entry := ocbinds.SchemaTree["Device"]
	for _, e := range elems {
		if entry == nil {
			return nil
		}
		entry = entry.Dir[unprefixed(e.GetName())]
	}
	if entry == nil || !entry.IsList() {
		return nil
	}

	res := make(map[string]bool)
	for _, name := range keyNames {
		leaf := entry.Dir[name]
		// Follow at most a short chain of leafrefs relative to the list.
		for i := 0; i < 4 && leaf != nil && leaf.Type != nil; i++ {
			kind := leaf.Type.Kind.String()
			if kind == "identityref" {
				res[name] = true
				break
			}
			if kind != "leafref" || !strings.HasPrefix(leaf.Type.Path, "../") ||
				strings.HasPrefix(leaf.Type.Path, "../../") {
				break
			}
			target := entry
			for _, part := range strings.Split(strings.TrimPrefix(leaf.Type.Path, "../"), "/") {
				if target == nil {
					break
				}
				target = target.Dir[unprefixed(part)]
			}
			leaf = target
		}
	}
	return res
}

func unprefixed(name string) string {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// listEntriesFromPayload unwraps the RFC 7951 object a list payload arrives in
// and returns its entries. An empty object is a list with no instances.
func listEntriesFromPayload(typedVal *gnmipb.TypedValue, listName string) ([]json.RawMessage, bool) {
	raw := typedVal.GetJsonIetfVal()
	if len(raw) == 0 {
		raw = typedVal.GetJsonVal()
	}
	if len(raw) == 0 {
		return nil, false
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, false
	}
	if len(wrapper) == 0 {
		return nil, true
	}
	inner, ok := jsonField(wrapper, listName)
	if !ok {
		return nil, false
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(inner, &entries); err != nil {
		return nil, false
	}
	return entries, true
}

// jsonNodeAt walks elems through a decoded RFC 7951 object and returns the
// node they name. An element with keys names the list entry carrying them.
func jsonNodeAt(fields map[string]json.RawMessage, elems []*gnmipb.PathElem) (json.RawMessage, bool) {
	for i, e := range elems {
		raw, ok := jsonField(fields, e.GetName())
		if !ok {
			return nil, false
		}
		if len(e.GetKey()) != 0 {
			if raw, ok = jsonListEntry(raw, e.GetKey()); !ok {
				return nil, false
			}
		}
		if i == len(elems)-1 {
			return raw, true
		}
		var next map[string]json.RawMessage
		if err := json.Unmarshal(raw, &next); err != nil {
			return nil, false
		}
		fields = next
	}
	return nil, false
}

// jsonListEntry returns the entry of an RFC 7951 list whose key leaves hold
// the given values.
func jsonListEntry(list json.RawMessage, keys map[string]string) (json.RawMessage, bool) {
	var entries []json.RawMessage
	if err := json.Unmarshal(list, &entries); err != nil {
		return nil, false
	}
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil {
			return nil, false
		}
		match := true
		for name, want := range keys {
			raw, found := jsonField(fields, name)
			if !found {
				match = false
				break
			}
			if got, ok := jsonScalarString(raw); !ok || got != want {
				match = false
				break
			}
		}
		if match {
			return entry, true
		}
	}
	return nil, false
}

// jsonField looks up a field of a decoded RFC 7951 object. Only nodes from a
// module other than their parent's are prefixed, so a name matches either
// form.
func jsonField(fields map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	if raw, ok := fields[name]; ok {
		return raw, true
	}
	for field, raw := range fields {
		if i := strings.IndexByte(field, ':'); i >= 0 && field[i+1:] == name {
			return raw, true
		}
	}
	return nil, false
}

// jsonScalarString renders a JSON scalar the way a path key spells it.
func jsonScalarString(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String(), true
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b), true
	}
	return "", false
}

func responsePath(prefix *gnmipb.Path, path *gnmipb.Path) *gnmipb.Path {
	if path == nil {
		return nil
	}
	p := proto.Clone(path).(*gnmipb.Path)
	stripOCModulePrefix(resolveGetStripOrigin(prefix, path), p)
	return p
}

// responseNotification returns a copy of a gNMI notification with module prefixes
// stripped from prefix, update, and delete paths when origin is openconfig.
func responseNotification(prefix *gnmipb.Path, n *gnmipb.Notification) *gnmipb.Notification {
	if n == nil {
		return nil
	}
	cloned := proto.Clone(n).(*gnmipb.Notification)
	cloned.Prefix = responsePath(prefix, cloned.Prefix)
	for _, u := range cloned.Update {
		u.Path = responsePath(prefix, u.Path)
	}
	for i, d := range cloned.Delete {
		cloned.Delete[i] = responsePath(prefix, d)
	}
	return cloned
}

// setPrefixTarget fills prefix taregt for given Notification objects.
func setPrefixTarget(notifs []*gnmipb.Notification, target string) {
	for _, n := range notifs {
		if n.Prefix == nil {
			n.Prefix = &gnmipb.Path{Target: target}
		} else {
			n.Prefix.Target = target
		}
	}
}

// Creates a spb.Value out of data from the translib according to the requested encoding.
func buildValue(prefix *gnmipb.Path, path *gnmipb.Path, enc gnmipb.Encoding,
	typedVal *gnmipb.TypedValue, valueTree ygot.ValidatedGoStruct) (*spb.Value, error) {

	switch enc {
	case gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF:
		if typedVal == nil {
			return nil, nil
		}
		return &spb.Value{
			Prefix:       prefix,
			Path:         responsePath(prefix, path),
			Timestamp:    time.Now().UnixNano(),
			SyncResponse: false,
			Val:          typedVal,
		}, nil

	case gnmipb.Encoding_PROTO:
		if valueTree == nil {
			return nil, nil
		}

		fullPath := transutil.GnmiTranslFullPath(prefix, path)
		removeLastPathElem(fullPath)
		notifications, err := ygot.TogNMINotifications(
			valueTree,
			time.Now().UnixNano(),
			ygot.GNMINotificationsConfig{
				UsePathElem:    true,
				PathElemPrefix: fullPath.GetElem(),
			})
		if err != nil {
			return nil, fmt.Errorf("Cannot convert OC Struct to Notifications: %s", err)
		}
		if len(notifications) != 1 {
			return nil, fmt.Errorf("YGOT returned wrong number of notifications")
		}
		if len(prefix.Target) != 0 {
			// Copy target from reqest.. ygot.TogNMINotifications does not fill it.
			setPrefixTarget(notifications, prefix.Target)
		}
		return &spb.Value{
			Notification: responseNotification(prefix, notifications[0]),
		}, nil
	default:
		return nil, fmt.Errorf("Unsupported Encoding %s", enc)
	}
}

// buildValueForGet generates a spb.Value for GetRequest.
// Besides the same function as buildValue, it generates spb.Value for nil value as well.
// Return: spb.Value is guaranteed not nil when error is nil.
func buildValueForGet(prefix *gnmipb.Path, path *gnmipb.Path, enc gnmipb.Encoding,
	typedVal *gnmipb.TypedValue, valueTree ygot.ValidatedGoStruct) (*spb.Value, error) {

	if spv, err := buildValue(prefix, path, enc, typedVal, valueTree); err != nil || spv != nil {
		return spv, err
	}

	// spv is nil. Server needs to generate Notification for GetRequest.
	switch enc {
	case gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF:
		return &spb.Value{
			Prefix:       prefix,
			Path:         responsePath(prefix, path),
			Timestamp:    time.Now().UnixNano(),
			SyncResponse: false,
			Val:          &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("{}")}},
		}, nil

	case gnmipb.Encoding_PROTO:
		// The Notification has no update and its prefix is the full path.
		fullPath := transutil.GnmiTranslFullPath(prefix, path)
		return &spb.Value{
			Notification: responseNotification(prefix, &gnmipb.Notification{
				Prefix:    fullPath,
				Timestamp: time.Now().UnixNano(),
			}),
		}, nil

	default:
		return nil, fmt.Errorf("Unsupported Encoding %s", enc)
	}
}
func (c *TranslClient) parseVersion() error {
	bv := getBundleVersion(c.extensions)
	if bv == nil {
		return nil
	}
	v, err := translib.NewVersion(*bv)
	if err != nil {
		c.version = &v
		return nil
	}
	log.V(4).Infof("Failed to parse version \"%s\"; err=%v", *bv, err)
	return fmt.Errorf("Invalid bundle version: %v", *bv)
}

func SetUseParallelProcessing(val bool) {
	*useParallelProcessing = val
}

type TranslClientOption interface {
	IsTranslClientOption()
}

type TranslWildcardOption struct{}

func (t TranslWildcardOption) IsTranslClientOption() {}

// TranslEncodingOption sets the encoding Get answers in. Subscribe takes its
// encoding from the SubscriptionList instead.
type TranslEncodingOption struct {
	Encoding gnmipb.Encoding
}

func (t TranslEncodingOption) IsTranslClientOption() {}
