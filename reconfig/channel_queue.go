package reconfig

// hotstuffMessageQueue serializes all producers through one channel-owned
// queue. The output is intentionally non-blocking for the existing protocol
// loop, which also performs timer and liveness work while idle.
type hotstuffMessageQueue struct {
	input chan *hotstuffMsg
	next  chan *hotstuffMsg
}

func newHotstuffMessageQueue() *hotstuffMessageQueue {
	q := &hotstuffMessageQueue{
		input: make(chan *hotstuffMsg, 4096),
		next:  make(chan *hotstuffMsg),
	}
	go q.run()
	return q
}

func (q *hotstuffMessageQueue) run() {
	queue := make([]*hotstuffMsg, 0, 256)
	for {
		var out chan *hotstuffMsg
		var next *hotstuffMsg
		if len(queue) > 0 {
			out = q.next
			next = queue[0]
		}
		select {
		case msg := <-q.input:
			if msg != nil {
				queue = append(queue, msg)
			}
		case out <- next:
			queue[0] = nil
			queue = queue[1:]
		}
	}
}

func (q *hotstuffMessageQueue) push(msg *hotstuffMsg) {
	if q != nil && msg != nil {
		q.input <- msg
	}
}

func (q *hotstuffMessageQueue) pop() *hotstuffMsg {
	if q == nil {
		return nil
	}
	select {
	case msg := <-q.next:
		return msg
	default:
		return nil
	}
}
