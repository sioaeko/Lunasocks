package pool

import "sync"

type Pool struct {
	pool sync.Pool
	size int
}

func New(size int) *Pool {
	return &Pool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

func (p *Pool) Get() []byte {
	buf := p.pool.Get().(*[]byte)
	return (*buf)[:p.size]
}

func (p *Pool) Put(buf []byte) {
	if cap(buf) >= p.size {
		b := buf[:p.size]
		p.pool.Put(&b)
	}
}

func (p *Pool) Size() int {
	return p.size
}
