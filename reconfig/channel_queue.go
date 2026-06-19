package reconfig

// hotstuffMessageQueue serializes all producers through one channel-owned
// queue. Local liveness messages use a priority lane so watchdog wakeups cannot
// sit behind a large burst of normal network messages.
type hotstuffMessageQueue struct {
	input         chan *hotstuffMsg
	priorityInput chan *hotstuffMsg
	next          chan *hotstuffMsg
}

func newHotstuffMessageQueue() *hotstuffMessageQueue {
	q := &hotstuffMessageQueue{
		input:         make(chan *hotstuffMsg, 65536),
		priorityInput: make(chan *hotstuffMsg, 8192),
		next:          make(chan *hotstuffMsg),
	}
	go q.run()
	return q
}

func (q *hotstuffMessageQueue) run() {
	priorityQueue := make([]*hotstuffMsg, 0, 64)
	queue := make([]*hotstuffMsg, 0, 256)
	for {
		select {
		case msg := <-q.priorityInput:
			if msg != nil {
				priorityQueue = append(priorityQueue, msg)
			}
			continue
		default:
		}

		var out chan *hotstuffMsg
		var next *hotstuffMsg
		usePriority := len(priorityQueue) > 0
		if usePriority {
			out = q.next
			next = priorityQueue[0]
		} else if len(queue) > 0 {
			out = q.next
			next = queue[0]
		}
		select {
		case msg := <-q.priorityInput:
			if msg != nil {
				priorityQueue = append(priorityQueue, msg)
			}
		case msg := <-q.input:
			if msg != nil {
				queue = append(queue, msg)
			}
		case out <- next:
			if usePriority {
				priorityQueue[0] = nil
				priorityQueue = priorityQueue[1:]
			} else {
				queue[0] = nil
				queue = queue[1:]
			}
		}
	}
}

func (q *hotstuffMessageQueue) push(msg *hotstuffMsg) {
	if q != nil && msg != nil {
		q.input <- msg
	}
}

func (q *hotstuffMessageQueue) pushPriority(msg *hotstuffMsg) {
	if q != nil && msg != nil {
		q.priorityInput <- msg
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
