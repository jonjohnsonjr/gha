package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v57/github"
	"golang.org/x/exp/slices"
)

func main() {
	ctx := context.Background()

	if err := mainE(ctx); err != nil {
		log.Fatal(err)
	}
}

func mainE(ctx context.Context) error {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	s := server{
		client: client,
	}

	log.Print("starting server...")
	http.HandleFunc("/trace", s.handler)
	http.HandleFunc("/", land)

	// Determine port for HTTP service.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defaulting to port %s", port)
	}

	// Start HTTP server.
	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		return fmt.Errorf("ListenAndServe: %w", err)
	}

	return nil
}

type server struct {
	client *github.Client
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())
	if err := s.handlerE(w, r); err != nil {
		log.Printf("handlerE: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *server) handleFilename(ctx context.Context, w http.ResponseWriter, r *http.Request, uri string) error {
	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")

	opt := &github.ListWorkflowRunsOptions{
		ListOptions: github.ListOptions{
			PerPage: 25,
		},
	}

	start := time.Unix(1<<62, 0)
	end := time.Unix(0, 0)

	allRuns := []*github.WorkflowRun{}
	for {
		runs, resp, err := s.client.Actions.ListWorkflowRunsByFileName(ctx, chunks[0], chunks[1], chunks[4], opt)
		if err != nil {
			return fmt.Errorf("ListWorkflowRunsByFileName: %w", err)
		}
		allRuns = append(allRuns, runs.WorkflowRuns...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage

		if len(allRuns) >= 50 {
			break
		}
	}

	allRuns = slices.DeleteFunc(allRuns, func(run *github.WorkflowRun) bool {
		return run.Conclusion == nil || *run.Conclusion == ""
	})

	slices.SortFunc(allRuns, func(a, b *github.WorkflowRun) int {
		return cmp.Compare(a.GetRunStartedAt().UnixMicro(), b.GetRunStartedAt().UnixMicro())
	})

	for _, j := range allRuns {
		if j.GetRunStartedAt().Before(start) {
			start = j.GetRunStartedAt().Time
		}
		if j.GetUpdatedAt().After(end) {
			end = j.GetUpdatedAt().Time
		}
		if j.GetRunStartedAt().After(end) {
			end = j.GetRunStartedAt().Time
		}
	}

	root := &Node{
		Span: &Span{
			Name:      uri,
			Href:      uri,
			StartTime: start,
			EndTime:   end,
		},
	}

	buildWorkflowRunTree(root, allRuns)

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	writeSpan(w, nil, root)
	fmt.Fprint(w, footer)

	return nil
}

func (s *server) handlePull(ctx context.Context, w http.ResponseWriter, r *http.Request, uri string) error {
	// TODO: Handle "/attempts/1"
	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")
	pull, err := strconv.Atoi(chunks[3])
	if err != nil {
		return err
	}

	pr, _, err := s.client.PullRequests.Get(ctx, chunks[0], chunks[1], pull)
	if err != nil {
		return fmt.Errorf("PullRequests.Get: %w", err)
	}

	opt := &github.ListCheckRunsOptions{
		// Filter: "all",
	}

	start := time.Unix(1<<62, 0)
	end := time.Unix(0, 0)

	allRuns := []*github.CheckRun{}
	for {
		runs, resp, err := s.client.Checks.ListCheckRunsForRef(ctx, chunks[0], chunks[1], pr.Head.GetSHA(), opt)
		if err != nil {
			return fmt.Errorf("ListCheckRunsForRef: %w", err)
		}
		allRuns = append(allRuns, runs.CheckRuns...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	slices.SortFunc(allRuns, func(a, b *github.CheckRun) int {
		return cmp.Compare(a.StartedAt.UnixMicro(), b.StartedAt.UnixMicro())
	})

	for _, j := range allRuns {
		if j.StartedAt.Before(start) {
			start = j.StartedAt.Time
		}
		if j.CompletedAt != nil && j.CompletedAt.After(end) {
			end = j.CompletedAt.Time
		}
		if j.StartedAt.After(end) {
			end = j.StartedAt.Time
		}
	}

	root := &Node{
		Span: &Span{
			Name:      uri,
			Href:      uri,
			StartTime: start,
			EndTime:   end,
		},
	}

	buildCheckTree(root, allRuns)

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	writeSpan(w, nil, root)
	fmt.Fprint(w, footer)

	return nil
}

func (s *server) handlerE(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	uri := r.URL.Query().Get("uri")

	if uri == "" {
		return nil
	}

	if strings.Contains(uri, "/pull/") {
		return s.handlePull(ctx, w, r, uri)
	}
	if strings.HasSuffix(uri, ".yaml") {
		return s.handleFilename(ctx, w, r, uri)
	}

	// TODO: Handle "/attempts/1"
	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")
	run, err := strconv.ParseInt(chunks[4], 10, 64)
	if err != nil {
		return err
	}

	owner, repo := chunks[0], chunks[1]
	opt := &github.ListWorkflowJobsOptions{
		// Filter: "all",
	}

	start := time.Unix(1<<62, 0)
	end := time.Unix(0, 0)

	allJobs := []*github.WorkflowJob{}

	if len(chunks) > 5 && chunks[5] == "job" {
		id, err := strconv.ParseInt(chunks[6], 10, 64)
		if err != nil {
			return err
		}
		job, _, err := s.client.Actions.GetWorkflowJobByID(ctx, owner, repo, id)
		if err != nil {
			return fmt.Errorf("GetWorkflowJobByID: %w", err)
		}

		allJobs = append(allJobs, job)
	} else {
		for {
			jobs, resp, err := s.client.Actions.ListWorkflowJobs(ctx, owner, repo, run, opt)
			if err != nil {
				return fmt.Errorf("ListWorkflowJobs: %w", err)
			}
			allJobs = append(allJobs, jobs.Jobs...)
			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	}

	slices.SortFunc(allJobs, func(a, b *github.WorkflowJob) int {
		return cmp.Compare(a.StartedAt.UnixMicro(), b.StartedAt.UnixMicro())
	})

	for _, j := range allJobs {
		if j.StartedAt.Before(start) {
			start = j.StartedAt.Time
		}
		if j.CompletedAt != nil && j.CompletedAt.After(end) {
			end = j.CompletedAt.Time
		}
		if j.StartedAt.After(end) {
			end = j.StartedAt.Time
		}
	}

	root := &Node{
		Span: &Span{
			Name:      uri,
			Href:      uri,
			StartTime: start,
			EndTime:   end,
		},
	}

	buildTree(owner, repo, end, root, allJobs)

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	writeSpan(w, nil, root)
	fmt.Fprint(w, footer)

	return nil
}

type Node struct {
	Span     *Span
	Children []*Node
}

func buildCheckTree(root *Node, runs []*github.CheckRun) {
	root.Children = make([]*Node, 0, len(runs))

	byGroup := map[string]*Node{}

	for _, r := range runs {
		run := &Span{
			Name:      r.GetName(),
			Href:      fmt.Sprintf("/trace?uri=%s", r.GetHTMLURL()), // TODO: Use HTMX to load this in-line.
			StartTime: r.StartedAt.Time,
		}
		if r.CompletedAt != nil {
			run.EndTime = r.CompletedAt.Time
		} else {
			run.EndTime = run.StartTime
			run.Flavor = "not finished"
		}

		if conc := r.GetConclusion(); conc != "success" {
			if conc != "" {
				run.Flavor = conc
			}
		}

		group, runName, ok := strings.Cut(run.Name, " / ")
		if !ok {
			root.Children = append(root.Children, &Node{
				Span: run,
			})

			continue
		}

		// If we got here, it's nested runs.
		run.Name = runName
		node, ok := byGroup[group]
		if !ok {
			node = &Node{
				Span: &Span{
					Name:      group,
					StartTime: run.StartTime,
					EndTime:   run.EndTime,
				},
				Children: []*Node{},
			}
			byGroup[group] = node

			// First time we hit this add it to root.
			root.Children = append(root.Children, node)
		}

		if run.EndTime.After(node.Span.EndTime) {
			node.Span.EndTime = run.EndTime
		}
		node.Children = append(node.Children, &Node{
			Span: run,
		})
	}

	slices.SortFunc(root.Children, func(a, b *Node) int {
		return a.Span.StartTime.Compare(b.Span.StartTime)
	})
}

func buildWorkflowRunTree(root *Node, runs []*github.WorkflowRun) {
	root.Children = make([]*Node, 0, len(runs))

	byGroup := map[string]*Node{}

	for _, r := range runs {
		run := &Span{
			Name:      r.GetName(),
			Href:      fmt.Sprintf("/trace?uri=%s", r.GetHTMLURL()), // TODO: Use HTMX to load this in-line.
			StartTime: r.GetRunStartedAt().Time,
		}
		run.EndTime = r.GetUpdatedAt().Time

		if conc := r.GetConclusion(); conc != "success" {
			if conc != "" {
				run.Flavor = conc
			}
		}

		group, runName, ok := strings.Cut(run.Name, " / ")
		if !ok {
			root.Children = append(root.Children, &Node{
				Span: run,
			})

			continue
		}

		// If we got here, it's nested runs.
		run.Name = runName
		node, ok := byGroup[group]
		if !ok {
			node = &Node{
				Span: &Span{
					Name:      group,
					StartTime: run.StartTime,
					EndTime:   run.EndTime,
				},
				Children: []*Node{},
			}
			byGroup[group] = node

			// First time we hit this add it to root.
			root.Children = append(root.Children, node)
		}

		if run.EndTime.After(node.Span.EndTime) {
			node.Span.EndTime = run.EndTime
		}
		node.Children = append(node.Children, &Node{
			Span: run,
		})
	}

	slices.SortFunc(root.Children, func(a, b *Node) int {
		return a.Span.StartTime.Compare(b.Span.StartTime)
	})
}

func buildTree(owner, repo string, end time.Time, root *Node, allJobs []*github.WorkflowJob) {
	root.Children = make([]*Node, 0, len(allJobs))

	byGroup := map[string]*Node{}

	for _, j := range allJobs {
		slices.SortFunc(j.Steps, func(a, b *github.TaskStep) int {
			return a.StartedAt.Compare(b.StartedAt.Time)
		})

		steps := make([]*Node, 0, len(j.Steps))

		for _, t := range j.Steps {
			task := &Span{
				Name:      t.GetName(),
				StartTime: t.StartedAt.Time,
			}
			if t.CompletedAt != nil {
				task.EndTime = t.CompletedAt.Time
			} else {
				task.EndTime = end
				task.Flavor = "not finished"
			}

			if conc := t.GetConclusion(); conc != "success" {
				if conc != "" {
					task.Flavor = conc
				}
				// TODO: Can we link to specific failures?
				task.FlavorHref = fmt.Sprintf("https://github.com/%s/%s/commit/%s/checks/%d/logs", owner, repo, j.GetHeadSHA(), j.GetID())
			}

			steps = append(steps, &Node{
				Span: task,
			})
		}

		job := &Span{
			Name:      j.GetName(),
			Href:      j.GetHTMLURL(),
			StartTime: j.StartedAt.Time,
		}

		if j.CompletedAt != nil {
			job.EndTime = j.CompletedAt.Time
		} else {
			job.EndTime = end
			job.Flavor = "not finished"
		}

		if conc := j.GetConclusion(); conc != "success" {
			if conc != "" {
				job.Flavor = conc
			}
			// There's an API for getting a logs URL but it doesn't seem to work actually (403).
			// TODO: Can we link to specific failures?
			job.FlavorHref = fmt.Sprintf("https://github.com/%s/%s/commit/%s/checks/%d/logs", owner, repo, j.GetHeadSHA(), j.GetID())
		}

		group, jobName, ok := strings.Cut(j.GetName(), " / ")
		if !ok {
			root.Children = append(root.Children, &Node{
				Span:     job,
				Children: steps,
			})

			continue
		}

		// If we got here, it's nested jobs.
		job.Name = jobName
		node, ok := byGroup[group]
		if !ok {
			node = &Node{
				Span: &Span{
					Name:      group,
					StartTime: job.StartTime,
					EndTime:   job.EndTime,
				},
				Children: []*Node{},
			}
			byGroup[group] = node

			// First time we hit this add it to root.
			root.Children = append(root.Children, node)
		}

		if job.EndTime.After(node.Span.EndTime) {
			node.Span.EndTime = job.EndTime
		}
		node.Children = append(node.Children, &Node{
			Span:     job,
			Children: steps,
		})
	}

	slices.SortFunc(root.Children, func(a, b *Node) int {
		return a.Span.StartTime.Compare(b.Span.StartTime)
	})
}

func writeSpan(w io.Writer, parent, node *Node) {
	if parent == nil {
		fmt.Fprint(w, `<div>`)
	} else {
		// TODO
		total := parent.Span.EndTime.Sub(parent.Span.StartTime)
		left := node.Span.StartTime.Sub(parent.Span.StartTime)
		right := parent.Span.EndTime.Sub(node.Span.EndTime)

		leftpad := float64(left) / float64(total)
		rightpad := float64(right) / float64(total)

		if len(node.Children) == 0 {
			fmt.Fprintf(w, `<div style="margin: 1px %f%% 0 %f%%">`, 100.0*rightpad, 100.0*leftpad)
		} else {
			fmt.Fprintf(w, `<div class="parent" style="margin: 1px %f%% 0 %f%%">`, 100.0*rightpad, 100.0*leftpad)
		}
	}

	dur := node.Span.EndTime.Sub(node.Span.StartTime)
	href := dur.String()
	if node.Span.Href != "" {
		href = fmt.Sprintf(`<a href=%q>%s</a>`, node.Span.Href, dur)
	}
	if flavor := node.Span.Flavor; flavor != "" {
		if fref := node.Span.FlavorHref; fref != "" {
			href += fmt.Sprintf(` (<a href=%q>%s</a>)`, fref, flavor)
		} else {
			href += fmt.Sprintf(` (%s)`, flavor)
		}
	}

	if len(node.Children) == 0 {
		if node.Span.Flavor == "failure" {
			fmt.Fprintf(w, `<span style="font-weight: bold; color:white; background-color: red">%s %s</span>`, node.Span.Name, href)
		} else {
			fmt.Fprintf(w, `<span>%s %s</span>`, node.Span.Name, href)
		}
	} else {
		if node.Span.Flavor == "failure" {
			fmt.Fprintf(w, `<details><summary style="font-weight: bold; color: white; background-color: red">%s %s</summary>`, node.Span.Name, href)
		} else {
			fmt.Fprintf(w, `<details><summary>%s %s</summary>`, node.Span.Name, href)
		}
		for _, child := range node.Children {
			writeSpan(w, node, child)
		}
		fmt.Fprint(w, `</details>`)
	}
	fmt.Fprint(w, `</div>`)
}

const header = `
<html>
<head>
<title>gha.dag.dev</title>
<style>
summary {
  border: 1px solid;
  display: block;
  white-space: nowrap;
  padding: 3px;
}
span {
  border: 1px solid;
  display: block;
  white-space: nowrap;
  padding: 3px;
}
body {
	font-family: monospace;
	width: 100%;
	margin: 0px;
}
div.parent:hover {
	outline: 1.5px solid lightgrey;
}
</style>
</head>
<body>`

const footer = `
    </body>
</html>
`

func land(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.svg" || r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "favicon.svg"))
		return
	}

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, "https://github.com/wolfi-dev/os/actions/runs/7390601887")
	fmt.Fprint(w, footer)
}

const landing = `
<h1>⏱️ GitHub Actions Trace Viewer</h1>
<form action="/trace" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="uri" value="%s"/>
<input type="submit" />
</form>
`

// Thank you mholt.
type Span struct {
	Name       string `json:"Name"`
	Href       string
	Flavor     string
	FlavorHref string
	StartTime  time.Time `json:"StartTime"`
	EndTime    time.Time `json:"EndTime"`
}
