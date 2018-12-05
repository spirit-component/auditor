package auditor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/go-spirit/spirit/cache"
	"github.com/go-spirit/spirit/component"
	"github.com/go-spirit/spirit/mail"
	"github.com/go-spirit/spirit/worker"

	"github.com/aliyun/aliyun-log-go-sdk"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"

	"github.com/spirit-component/auditor/internal/queue/goring"
)

var (
	goringInitSize int64 = 64
)

type HeaderDiff struct {
	Added    map[string]string `json:"added,omitempty"`
	Deleted  map[string]string `json:"deleted,omitempty"`
	Modified map[string]string `json:"modified,omitempty"`
}

type Audit struct {
	opts component.Options

	alias string

	aesKey []byte

	cache cache.Cache

	logStore  *sls.LogStore
	queue     *goring.Queue
	logSize   int64
	bodyLimit int

	topic  string
	source string

	interval time.Duration

	stopChan    chan struct{}
	stoppedChan chan struct{}

	filters      map[string]*regexFilter
	filtersOrder []string
}

type regexFilter struct {
	r    *regexp.Regexp
	Expr string
	Repl string
}

func (p *regexFilter) Filter(src []byte) []byte {
	return p.r.ReplaceAll(src, []byte(p.Repl))
}

func newRegexFilter(expr string, repl string) (*regexFilter, error) {
	r, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}

	return &regexFilter{
		r:    r,
		Expr: expr,
		Repl: repl,
	}, nil
}

func init() {
	component.RegisterComponent("auditor", NewAudit)
}

func NewAudit(alias string, opts ...component.Option) (comp component.Component, err error) {

	auditOpts := component.Options{}

	for _, o := range opts {
		o(&auditOpts)
	}

	return &Audit{
		alias: alias,
		opts:  auditOpts,
	}, nil
}

func (p *Audit) Start() (err error) {

	slsEndPoint := p.opts.Config.GetString("sls.endpoint")

	if len(slsEndPoint) == 0 {
		err = fmt.Errorf("sls.endpoint is empty")
		return
	}

	slsAccessKeyId := p.opts.Config.GetString("sls.access-key-id")

	if len(slsAccessKeyId) == 0 {
		err = fmt.Errorf("sls.access-key-id is empty")
		return
	}

	slsAccessKeySecret := p.opts.Config.GetString("sls.access-key-secret")

	if len(slsAccessKeySecret) == 0 {
		err = fmt.Errorf("sls.access-key-secret is empty")
		return
	}

	slsProject := p.opts.Config.GetString("sls.project")

	if len(slsProject) == 0 {
		err = fmt.Errorf("sls.project is empty")
		return
	}

	slsStore := p.opts.Config.GetString("sls.store")

	if len(slsStore) == 0 {
		err = fmt.Errorf("sls.store is empty")
		return
	}

	slsTopic := p.opts.Config.GetString("sls.topic")
	slsSource := p.opts.Config.GetString("sls.source")

	logInterval := p.opts.Config.GetTimeDuration("report.interval", time.Second)

	logProj, err := sls.NewLogProject(slsProject, slsEndPoint, slsAccessKeyId, slsAccessKeySecret)
	if err != nil {
		return
	}

	logStore, err := sls.NewLogStore(slsStore, logProj)
	if err != nil {
		return
	}

	auditCache, exist := p.opts.Caches.Require("audit")
	if !exist {
		err = fmt.Errorf("the cache of 'audit' not exist")
		return
	}

	filtersConfig := p.opts.Config.GetConfig("report.filters")

	var filters map[string]*regexFilter
	var filtersOrder []string

	if !filtersConfig.IsEmpty() {
		filters = make(map[string]*regexFilter)
		for _, k := range filtersConfig.Keys() {
			expr := filtersConfig.GetString(k + ".expr")
			repl := filtersConfig.GetString(k + ".repl")
			reg, errReg := newRegexFilter(expr, repl)
			if errReg != nil {
				return errReg
			}
			filters[k] = reg
		}
		filtersOrder = filtersConfig.Keys()
	}

	p.logStore = logStore
	p.cache = auditCache
	p.logSize = p.opts.Config.GetInt64("report.log-size", 10)
	p.bodyLimit = int(p.opts.Config.GetInt64("report.body-limit", 0))
	p.queue = goring.New(goringInitSize)
	p.topic = slsTopic
	p.source = slsSource
	p.interval = logInterval
	p.stopChan = make(chan struct{})
	p.stoppedChan = make(chan struct{})
	p.filters = filters
	p.filtersOrder = filtersOrder

	go p.postWorker()

	return nil
}

func (p *Audit) Stop() error {

	p.stopChan <- struct{}{}
	<-p.stoppedChan

	return nil
}

func (p *Audit) Alias() string {
	if p == nil {
		return ""
	}
	return p.alias
}

type AuditContent struct {
	Id        string
	Header    map[string]string
	BeginBody []byte
	EndBody   []byte
	Err       error
	BeginTime time.Time
	EndTime   time.Time
	BeginFrom string
	EndFrom   string
}

func (p *Audit) Begin(session mail.Session) (err error) {

	id := session.Payload().ID()
	header := copyHeader(session.Payload().Content().GetHeader())

	var body = copyBytes(session.Payload().Content().GetBody())

	if p.bodyLimit > 0 && len(body) > p.bodyLimit {
		body = append(body[:p.bodyLimit], []byte("......")...)
	}

	body = p.appleFilters(body)

	sErr := session.Err()

	p.cache.Set(id, &AuditContent{
		Id:        id,
		Header:    header,
		BeginBody: body,
		Err:       sErr,
		BeginTime: time.Now().UTC(),
		BeginFrom: session.From(),
	},
	)

	return
}

func (p *Audit) End(session mail.Session) (err error) {

	id := session.Payload().ID()
	sErr := session.Err()

	icontent, exist := p.cache.Get(id)

	if !exist {
		return
	}

	p.cache.Delete(id)

	content, ok := icontent.(*AuditContent)

	if !ok {
		return
	}

	if content == nil {
		return
	}

	if sErr != nil {
		content.Err = sErr // update response err
	}

	strHeader := ""

	if len(content.Header) > 0 {
		data, _ := json.Marshal(content.Header)
		data = p.appleFilters(data)
		strHeader = string(data)
	}

	content.EndTime = time.Now().UTC()
	content.EndFrom = session.From()

	var body = copyBytes(session.Payload().Content().GetBody())

	if p.bodyLimit > 0 && len(body) > p.bodyLimit {
		body = append(body[:p.bodyLimit], []byte("......")...)
	}

	body = p.appleFilters(body)

	content.EndBody = body

	slsLog := &sls.Log{
		Time: proto.Uint32(uint32(content.BeginTime.Unix())),
		Contents: []*sls.LogContent{
			&sls.LogContent{
				Key:   proto.String("id"),
				Value: proto.String(content.Id),
			},
			&sls.LogContent{
				Key:   proto.String("header"),
				Value: proto.String(string(strHeader)),
			},
			&sls.LogContent{
				Key:   proto.String("timestamp"),
				Value: proto.String(content.BeginTime.String()),
			},
			&sls.LogContent{
				Key:   proto.String("time_costs"),
				Value: proto.String(fmt.Sprintf("%0.10fs", content.EndTime.Sub(content.BeginTime).Seconds())),
			},
		},
	}

	if content.Err != nil {
		slsLog.Contents = append(slsLog.Contents,
			&sls.LogContent{
				Key:   proto.String("error"),
				Value: proto.String(content.Err.Error()),
			})
	}

	ckPoint := session.Query("checkpoint")
	if len(ckPoint) > 0 {
		slsLog.Contents = append(slsLog.Contents,
			&sls.LogContent{
				Key:   proto.String("checkpoint"),
				Value: proto.String(ckPoint),
			},
		)
	}

	if session.Query("action") != "step" {

		hd := createHeaderDiff(content.Header, session.Payload().Content().GetHeader())

		headerDiffData, _ := json.Marshal(hd)
		strHeaderDiff := string(p.appleFilters(headerDiffData))

		slsLog.Contents = append(slsLog.Contents,
			&sls.LogContent{
				Key:   proto.String("header_diff"),
				Value: proto.String(strHeaderDiff),
			},
			&sls.LogContent{
				Key:   proto.String("begin_from"),
				Value: proto.String(content.BeginFrom),
			},
			&sls.LogContent{
				Key:   proto.String("end_from"),
				Value: proto.String(content.EndFrom),
			},
			&sls.LogContent{
				Key:   proto.String("begin_body"),
				Value: proto.String(string(content.BeginBody)),
			},
			&sls.LogContent{
				Key:   proto.String("end_body"),
				Value: proto.String(string(content.EndBody)),
			},
			&sls.LogContent{
				Key:   proto.String("mode"),
				Value: proto.String("paired"),
			},
		)
	} else {
		slsLog.Contents = append(slsLog.Contents,
			&sls.LogContent{
				Key:   proto.String("from"),
				Value: proto.String(content.BeginFrom),
			},
			&sls.LogContent{
				Key:   proto.String("body"),
				Value: proto.String(string(content.BeginBody)),
			},
			&sls.LogContent{
				Key:   proto.String("mode"),
				Value: proto.String("single"),
			},
		)
	}

	p.queue.Push(slsLog)

	return
}

func copyBytes(data []byte) []byte {
	var newBytes = make([]byte, len(data), cap(data))
	copy(newBytes, data)
	return newBytes
}

func (p *Audit) Step(session mail.Session) (err error) {
	p.Begin(session)
	p.End(session)

	return
}

func (p *Audit) postWorker() {

	tick := time.Tick(p.interval)

	for {
		select {
		case <-tick:
			{
				ilogs, ok := p.queue.PopMany(p.logSize)

				if !ok {
					continue
				}

				lg := p.toLogGroup(ilogs)

				if lg == nil {
					continue
				}

				err := p.logStore.PutLogs(lg)

				if err != nil {
					logrus.WithError(err).Errorln("autdit logs failure")
				}
			}

		case <-p.stopChan:
			{
				if p.queue.Length() > 0 {
					go func() {
						time.Sleep(time.Second)
						p.stopChan <- struct{}{}
					}()
					continue
				}

				p.stoppedChan <- struct{}{}
				return
			}
		}
	}
}

func (p *Audit) toLogGroup(logs []interface{}) *sls.LogGroup {
	if len(logs) == 0 {
		return nil
	}

	logGroup := &sls.LogGroup{
		Source: proto.String(p.source),
		Topic:  proto.String(p.topic),
	}

	for _, v := range logs {
		l, ok := v.(*sls.Log)
		if ok {
			logGroup.Logs = append(logGroup.Logs, l)
		}
	}

	if len(logGroup.Logs) > 0 {
		return logGroup
	}

	return nil
}

func (p *Audit) appleFilters(src []byte) []byte {
	for _, k := range p.filtersOrder {
		f, exist := p.filters[k]
		if !exist {
			continue
		}
		src = f.Filter(src)
	}
	return src
}

func (p *Audit) Route(session mail.Session) worker.HandlerFunc {

	switch session.Query("action") {
	case "begin":
		{
			return p.Begin
		}
	case "end":
		{
			return p.End
		}
	case "step":
		{
			return p.Step
		}
	}

	return nil
}

func copyHeader(header map[string]string) map[string]string {
	if header == nil {
		return nil
	}

	n := make(map[string]string)

	for k, v := range header {
		n[k] = v
	}

	return n
}

func createHeaderDiff(oldHeader map[string]string, newHeader map[string]string) HeaderDiff {

	diff := HeaderDiff{}

	for k, v := range newHeader {

		oldV, exist := oldHeader[k]

		if exist {
			if oldV != v {
				if diff.Modified == nil {
					diff.Modified = make(map[string]string)
				}
				diff.Modified[k] = v
			}
		} else {
			if diff.Added == nil {
				diff.Added = make(map[string]string)
			}
			diff.Added[k] = v
		}
	}

	for k, v := range oldHeader {
		_, exist := newHeader[k]

		if !exist {
			if diff.Deleted == nil {
				diff.Deleted = make(map[string]string)
			}
			diff.Deleted[k] = v
		}
	}

	return diff
}
