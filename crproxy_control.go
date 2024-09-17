package crproxy

import (
	"net/http"
	"time"

	"github.com/wzshiming/geario"
)

func (c *CRProxy) checkLimit(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		bps, _ := c.speedLimitRecord.LoadOrStore(r.RemoteAddr, geario.NewBPSAver(c.ipsSpeedLimitDuration))
		aver := bps.Aver()
		if aver > *c.ipsSpeedLimit {
			if c.logger != nil {
				c.logger.Println("exceed limit", r.RemoteAddr, aver, *c.ipsSpeedLimit)
			}
			for bps.Aver() > *c.ipsSpeedLimit {
				wait := time.Second
				n := bps.Next()
				if !n.IsZero() {
					wait = bps.Next().Sub(time.Now())
					if wait < time.Second {
						wait = time.Second
					}
				}
				select {
				case <-r.Context().Done():
					return false
				case <-time.After(wait):
				}
			}
		}
	}

	return true
}

func (c *CRProxy) waitForLimit(r *http.Request, info *PathInfo, size int64) bool {
	if c.blobsSpeedLimit != nil && info.Blobs != "" {
		dur := GetSleepDuration(geario.B(size), *c.blobsSpeedLimit, c.blobsSpeedLimitDuration)
		if dur > 0 {
			if c.logger != nil {
				c.logger.Println("delay request", r.RemoteAddr, geario.B(size), dur)
			}
			select {
			case <-r.Context().Done():
				return false
			case <-time.After(dur):
			}
		}
	}

	return true
}

func (c *CRProxy) accumulativeLimit(r *http.Request, info *PathInfo, size int64) {
	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		bps, ok := c.speedLimitRecord.Load(r.RemoteAddr)
		if ok {
			bps.Add(geario.B(size))
		}
	}
}
