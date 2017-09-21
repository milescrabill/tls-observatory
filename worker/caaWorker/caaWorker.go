package caaWorker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "caaWorker"
	workerDesc = ""

	log = logger.GetLogger()
)

func init() {
	worker.RegisterWorker(workerName, worker.Info{Runner: new(eval), Description: workerDesc})
}

// Result describes the result produced by CAAWorker
type Result struct {
	Host         string   `json:"host"`
	IssueCAs     []string `json:"issue_cas"`
	IssueWildCAs []string `json:"issuewild_cas"`
	Valid        bool     `json:"valid"`
}

type eval struct{}

// Run implements the worker interface.It is called to get the worker results.
func (e eval) Run(in worker.Input, resChan chan worker.Result) {
	result := worker.Result{WorkerName: workerName}
	caaRes := Result{}

	var matchingHost string

	hostPieces := strings.Split(in.Target, ".")
	for i := 0; i < len(hostPieces); i++ {
		host := strings.Join(hostPieces[i:], ".")

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeCAA)

		client := dns.Client{}
		res, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("CAA lookup failed for %s: %v", host, err))
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			result.Errors = append(result.Errors, fmt.Sprintf("CAA lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
			continue
		}

		for _, rr := range res.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				matchingHost = host
				if caa.Tag == "issue" {
					caaRes.IssueCAs = append(caaRes.IssueCAs, caa.Value)
				} else if caa.Tag == "issuewild" {
					caaRes.IssueWildCAs = append(caaRes.IssueWildCAs, caa.Value)
				}
			}
		}
		if matchingHost != "" {
			break
		}
	}

	if matchingHost != "" {
		//to mark success we should check if the CA found in CAA record matches the actual one
		result.Success = true
	}

	res, err := json.Marshal(caaRes)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	result.Result = res

	resChan <- result
}

// Assertor compares 2 caaResults and reports differences.
func (e eval) Assertor(caaResult, assertresults []byte) (pass bool, body []byte, err error) {
	var result, assertres Result
	err = json.Unmarshal(caaResult, &result)
	if err != nil {
		return
	}
	err = json.Unmarshal(assertresults, &assertres)
	if err != nil {
		return
	}
	if result.Valid != assertres.Valid || result.Host != assertres.Host {
		body = []byte(fmt.Sprintf(`Assertion failed MatchedHost= %s, CAAValid= %t`,
			result.Host, result.Valid))
		pass = false
	} else {
		pass = true
	}
	return
}
