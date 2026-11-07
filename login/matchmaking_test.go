package login

import (
	"bytes"
	"net"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// fakeQueue records the calls and returns a fixed result.
type fakeQueue struct {
	enqueued  []int32
	veh       []byte
	dequeued  int64
	censusFor []uint8
	result    QueueResult
	players   int
	classes   []int
}

func (f *fakeQueue) Enqueue(_ int64, _ string, args []int32, veh []byte) QueueResult {
	f.enqueued = args
	f.veh = veh
	return f.result
}
func (f *fakeQueue) Dequeue(accountID int64) bool {
	f.dequeued = accountID
	return true
}
func (f *fakeQueue) Census(queueType uint8) (int, []int) {
	f.censusFor = append(f.censusFor, queueType)
	return f.players, f.classes
}

// queueServer builds a server with the Account dispatch and a fake queue.
func queueServer(t *testing.T, q *fakeQueue) *BaseAppServer {
	t.Helper()
	s := tokenTestServer(t, nil)
	s.cfg.Queue = &QueueHooks{
		Enqueue: q.Enqueue,
		Dequeue: q.Dequeue,
		Census:  q.Census,
	}
	return s
}

// queueCall builds a postCall for one queue command.
func queueCall(t *testing.T, s *BaseAppServer, method string, args ...entdef.Value) postCall {
	t.Helper()
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, method)
	if m == nil {
		t.Fatalf("no %s in the Account base methods", method)
	}
	call := postCall{Method: m, Args: args}
	if len(args) > 0 {
		call.Req = uint16(uintOf(args[0]))
	}
	if len(args) > 1 {
		call.Cmd = uint16(uintOf(args[1]))
	}
	return call
}

// intArr wraps a list of ints as an ARRAY<INT64> argument.
func intArr(vals ...int64) entdef.Value {
	seq := make([]entdef.Value, 0, len(vals))
	for _, v := range vals {
		seq = append(seq, entdef.Value{Kind: entdef.VInt, Int: v})
	}
	return entdef.Value{Kind: entdef.VSeq, Seq: seq}
}

// clientElemID resolves a client method's element id from the defs, so a
// test never pins a number the table can legitimately move.
func clientElemID(t *testing.T, s *BaseAppServer, name string) byte {
	t.Helper()
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		t.Fatal("no Account entity")
	}
	for i := range acct.ClientMethods {
		if acct.ClientMethods[i].Name == name {
			return byte(entityMethodBase + i)
		}
	}
	t.Fatalf("no client method %q", name)
	return 0
}

// TestEnqueueAnswersOnEnqueued checks the success path: the client gets
// Account.onEnqueued(queueType) and the vehicle is resolved from the
// session's garage.
func TestEnqueueAnswersOnEnqueued(t *testing.T) {
	q := &fakeQueue{result: QueueResult{Added: 1}}
	s := queueServer(t, q)
	veh := lobby.AllOwnableVehicles[0].CompDescr
	call := queueCall(t, s, "doCmdIntArr",
		entdef.Value{Kind: entdef.VInt, Int: 202}, // REQUEST_ID_NO_RESPONSE
		entdef.Value{Kind: entdef.VInt, Int: 700}, // CMD_ENQUEUE_IN_BATTLE_QUEUE
		intArr(1, 42, 0, 0, 0),
	)
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		garage: []GarageItem{{InvID: 42, CompactDescr: veh}},
	}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(q.enqueued) != 5 || q.enqueued[0] != 1 || q.enqueued[1] != 42 {
		t.Fatalf("enqueue args = %v", q.enqueued)
	}
	if !bytes.Equal(q.veh, veh) {
		t.Fatalf("vehicle = % x, want the session's descriptor", q.veh)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes, want 1", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	// The app is the tick (13 00) then the element: id then the queue
	// type — a fixed-size method carries no length field.
	if len(app) < 4 || app[2] != clientElemID(t, s, "onEnqueued") {
		t.Fatalf("answer is not onEnqueued: % x", app)
	}
	if app[3] != 1 {
		t.Fatalf("queue type = %d, want 1", app[3])
	}
}

// TestEnqueueAnswersOnEnqueueFailure checks the refusal path: the client
// gets Account.onEnqueueFailure(queueType, code, message).
func TestEnqueueAnswersOnEnqueueFailure(t *testing.T) {
	q := &fakeQueue{result: QueueResult{Code: 4, Message: "the vehicle is not in the garage"}}
	s := queueServer(t, q)
	call := queueCall(t, s, "doCmdIntArr",
		entdef.Value{Kind: entdef.VInt, Int: 202},
		entdef.Value{Kind: entdef.VInt, Int: 700},
		intArr(1, 99, 0, 0, 0),
	)
	// The garage does not hold inventory id 99, so the vehicle is nil.
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if q.veh != nil {
		t.Fatalf("vehicle = % x, want nil for an unknown inventory id", q.veh)
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if len(app) < 3 || app[2] != clientElemID(t, s, "onEnqueueFailure") {
		t.Fatalf("answer is not onEnqueueFailure: % x", app)
	}
	if !bytes.Contains(app, []byte("not in the garage")) {
		t.Fatalf("error string missing: % x", app)
	}
}

// TestDequeueAnswersOnDequeued checks the leave path.
func TestDequeueAnswersOnDequeued(t *testing.T) {
	q := &fakeQueue{}
	s := queueServer(t, q)
	call := queueCall(t, s, "doCmdInt",
		entdef.Value{Kind: entdef.VInt, Int: 202},
		entdef.Value{Kind: entdef.VInt, Int: 701}, // CMD_DEQUEUE_FROM_BATTLE_QUEUE
		entdef.Value{Kind: entdef.VInt, Int: 1},   // QUEUE_TYPE.RANDOMS
	)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if q.dequeued != 2 {
		t.Fatalf("dequeued account = %d, want 2", q.dequeued)
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	// onDequeued is a fixed-size client method.
	if len(app) < 4 || app[2] != clientElemID(t, s, "onDequeued") || app[3] != 1 {
		t.Fatalf("answer is not onDequeued(1): % x", app)
	}
}

// TestQueueInfoPassesTheQueueType checks that the census is asked for the
// queue the client is polling, not for every queue at once.
func TestQueueInfoPassesTheQueueType(t *testing.T) {
	q := &fakeQueue{players: 3, classes: []int{1, 1, 1, 0, 0}}
	s := queueServer(t, q)
	call := queueCall(t, s, "doCmdInt3",
		entdef.Value{Kind: entdef.VInt, Int: 202},
		entdef.Value{Kind: entdef.VInt, Int: 502}, // CMD_REQ_QUEUE_INFO
		entdef.Value{Kind: entdef.VInt, Int: 1},   // queueType
		entdef.Value{Kind: entdef.VInt, Int: 0},
		entdef.Value{Kind: entdef.VInt, Int: 0},
	)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(q.censusFor) != 1 || q.censusFor[0] != 1 {
		t.Fatalf("census asked for %v, want [1]", q.censusFor)
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if !bytes.Contains(app, []byte{0x1a, smallQueueInfo}) {
		t.Fatalf("answer is not the 1a/67 census: % x", app)
	}
}
