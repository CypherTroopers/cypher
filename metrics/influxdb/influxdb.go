package influxdb

import (
	stdlog "log"
	"time"

	"github.com/cypherium/cypher/metrics"
	client "github.com/influxdata/influxdb1-client/v2"
)

func InfluxDB(r metrics.Registry, d time.Duration, endpoint, database, username, password string) {
	InfluxDBWithTags(r, d, endpoint, database, username, password, "cypher.", nil)
}

func InfluxDBWithTags(r metrics.Registry, d time.Duration, endpoint, database, username, password string, namespace string, tags map[string]string) {
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     endpoint,
		Username: username,
		Password: password,
	})
	if err != nil {
		stdlog.Printf("influxdb: failed to create client: %v", err)
		return
	}
	defer c.Close()

	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for range ticker.C {
		if err := writeRegistry(c, r, database, namespace, tags); err != nil {
			stdlog.Printf("influxdb: failed to write metrics: %v", err)
		}
	}
}

func writeRegistry(c client.Client, r metrics.Registry, database string, namespace string, tags map[string]string) error {
	bp, err := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  database,
		Precision: "ns",
	})
	if err != nil {
		return err
	}

	now := time.Now()

	r.Each(func(name string, item interface{}) {
		fields := metricFields(item)
		if len(fields) == 0 {
			return
		}

		point, err := client.NewPoint(namespace+name, copyTags(tags), fields, now)
		if err != nil {
			return
		}
		bp.AddPoint(point)
	})

	return c.Write(bp)
}

func copyTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	copied := make(map[string]string, len(tags))
	for k, v := range tags {
		copied[k] = v
	}
	return copied
}

func metricFields(item interface{}) map[string]interface{} {
	fields := make(map[string]interface{})

	switch m := item.(type) {
	case metrics.Counter:
		fields["count"] = m.Count()

	case metrics.Gauge:
		fields["value"] = m.Value()

	case metrics.GaugeFloat64:
		fields["value"] = m.Value()

	case metrics.Histogram:
		ps := m.Percentiles([]float64{0.50, 0.75, 0.95, 0.99, 0.999})
		fields["count"] = m.Count()
		fields["min"] = m.Min()
		fields["max"] = m.Max()
		fields["mean"] = m.Mean()
		fields["stddev"] = m.StdDev()
		fields["p50"] = ps[0]
		fields["p75"] = ps[1]
		fields["p95"] = ps[2]
		fields["p99"] = ps[3]
		fields["p999"] = ps[4]

	case metrics.Meter:
		fields["count"] = m.Count()
		fields["m1"] = m.Rate1()
		fields["m5"] = m.Rate5()
		fields["m15"] = m.Rate15()
		fields["mean"] = m.RateMean()

	case metrics.Timer:
		ps := m.Percentiles([]float64{0.50, 0.75, 0.95, 0.99, 0.999})
		fields["count"] = m.Count()
		fields["min"] = m.Min()
		fields["max"] = m.Max()
		fields["mean"] = m.Mean()
		fields["stddev"] = m.StdDev()
		fields["p50"] = ps[0]
		fields["p75"] = ps[1]
		fields["p95"] = ps[2]
		fields["p99"] = ps[3]
		fields["p999"] = ps[4]
		fields["m1"] = m.Rate1()
		fields["m5"] = m.Rate5()
		fields["m15"] = m.Rate15()
		fields["rate_mean"] = m.RateMean()
	}

	return fields
}
