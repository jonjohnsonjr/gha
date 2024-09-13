package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	bufra "github.com/avvmoto/buf-readerat"
	"github.com/snabb/httpreaderat"

	"github.com/google/go-github/v57/github"
	"golang.org/x/exp/slices"

	hgzip "github.com/nanmu42/gzip"
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
		oauth2: &oauth2.Config{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		},
	}

	log.Print("starting server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/trace", s.handler)
	mux.HandleFunc("/api/github/hook", s.webhook)
	mux.HandleFunc("/callback", s.callback)
	mux.HandleFunc("/auth", s.auth)
	mux.HandleFunc("/", land)

	// Determine port for HTTP service.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defaulting to port %s", port)
	}

	// Start HTTP server.
	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, hgzip.DefaultHandler().WrapHandler(mux)); err != nil {
		return fmt.Errorf("ListenAndServe: %w", err)
	}

	return nil
}

type server struct {
	client *github.Client

	// TODO: Use this.
	oauth2 *oauth2.Config
}

func (s *server) Client(r *http.Request) *github.Client {
	if cookie, err := r.Cookie("gh_access_token"); err == nil {
		return github.NewClient(nil).WithAuthToken(cookie.Value)
	} else {
		log.Printf("cookie error: %v", err)
	}

	return s.client
}

func (s *server) webhook(w http.ResponseWriter, r *http.Request) {
}

type TokenResp struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`

	TokenType string `json:"token_type,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if err := func() error {
		u, err := url.Parse("https://github.com/login/oauth/access_token")
		if err != nil {
			return err
		}

		q := u.Query()
		q.Set("client_id", os.Getenv("GITHUB_CLIENT_ID"))
		q.Set("client_secret", os.Getenv("GITHUB_CLIENT_SECRET"))
		q.Set("code", code)
		q.Set("redirect_uri", "https://gha.dag.dev/callback")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Add("Accept", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("POST: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}

		var tok TokenResp
		if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
			return fmt.Errorf("decode: %w", err)
		}

		atCookie := &http.Cookie{
			Name:     "gh_access_token",
			Value:    tok.AccessToken,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(time.Second * time.Duration(tok.ExpiresIn)),
		}
		http.SetCookie(w, atCookie)

		rtCookie := &http.Cookie{
			Name:     "gh_refresh_token",
			Value:    tok.RefreshToken,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(time.Second * time.Duration(tok.RefreshTokenExpiresIn)),
		}
		http.SetCookie(w, rtCookie)

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return nil
	}(); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (s *server) auth(w http.ResponseWriter, r *http.Request) {
	if err := func() error {
		u, err := url.Parse("https://github.com/login/oauth/authorize")
		if err != nil {
			return err
		}

		q := u.Query()
		q.Set("client_id", os.Getenv("GITHUB_CLIENT_ID"))
		q.Set("redirect_uri", "https://gha.dag.dev/callback")

		u.RawQuery = q.Encode()

		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)

		return nil
	}(); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
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

	start := time.Now()
	end := time.Unix(0, 0)

	allRuns := []*github.WorkflowRun{}
	for {
		runs, resp, err := s.Client(r).Actions.ListWorkflowRunsByFileName(ctx, chunks[0], chunks[1], chunks[4], opt)
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
		return compareTimestamp(a.RunStartedAt, b.RunStartedAt)
	})

	for _, j := range allRuns {
		if rsa := j.RunStartedAt; rsa != nil {
			if rsa.Before(start) {
				start = rsa.Time
			}
			if rsa.After(end) {
				end = rsa.Time
			}
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

	pr, _, err := s.Client(r).PullRequests.Get(ctx, chunks[0], chunks[1], pull)
	if err != nil {
		return fmt.Errorf("PullRequests.Get: %w", err)
	}

	opt := &github.ListCheckRunsOptions{
		// Filter: "all",
	}

	start := time.Now()
	end := time.Unix(0, 0)

	allRuns := []*github.CheckRun{}
	for {
		runs, resp, err := s.Client(r).Checks.ListCheckRunsForRef(ctx, chunks[0], chunks[1], pr.Head.GetSHA(), opt)
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
		return compareTimestamp(a.StartedAt, b.StartedAt)
	})

	for _, j := range allRuns {
		if started := j.StartedAt; started != nil {
			if started.Before(start) {
				start = started.Time
			}
			if started.After(end) {
				end = started.Time
			}
		}
		if j.CompletedAt == nil {
			end = time.Now()
		} else if j.CompletedAt.After(end) {
			end = j.CompletedAt.Time
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

	if art := r.URL.Query().Get("artifact"); art != "" {
		if name := r.URL.Query().Get("name"); strings.HasPrefix(name, "logs-") {
			return s.renderLogs(w, r, art)
		} else if name == "coverage" {
			return s.renderCoverage(w, r, art)
		} else {
			return s.renderTrot(w, r, art)
		}
	}

	owner, repo := chunks[0], chunks[1]
	opt := &github.ListWorkflowJobsOptions{
		// Filter: "all",
	}

	lopt := &github.ListOptions{}
	artifacts, _, err := s.Client(r).Actions.ListWorkflowRunArtifacts(ctx, owner, repo, run, lopt)
	if err != nil {
		return fmt.Errorf("listing artifacts: %w", err)
	}

	files := []*github.Artifact{}
	for _, artifact := range artifacts.Artifacts {
		name := artifact.GetName()
		if strings.HasPrefix(name, "trace-") || strings.HasPrefix(name, "logs-") || name == "coverage" {
			files = append(files, artifact)
		}
	}

	start := time.Now()
	end := time.Unix(0, 0)

	allJobs := []*github.WorkflowJob{}

	if len(chunks) > 5 && chunks[5] == "job" {
		id, err := strconv.ParseInt(chunks[6], 10, 64)
		if err != nil {
			return err
		}
		job, _, err := s.Client(r).Actions.GetWorkflowJobByID(ctx, owner, repo, id)
		if err != nil {
			return fmt.Errorf("GetWorkflowJobByID: %w", err)
		}

		allJobs = append(allJobs, job)

	} else {
		for {
			jobs, resp, err := s.Client(r).Actions.ListWorkflowJobs(ctx, owner, repo, run, opt)
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
		return compareTimestamp(a.StartedAt, b.StartedAt)
	})

	for _, j := range allJobs {
		if started := j.StartedAt; started != nil {
			if started.Before(start) {
				start = started.Time
			}
			if started.After(end) {
				end = started.Time
			}
		}
		if j.CompletedAt == nil {
			end = time.Now()
		} else if j.CompletedAt.After(end) {
			end = j.CompletedAt.Time
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
	if len(files) != 0 {
		fmt.Fprintf(w, "<h3>Artifacts</h3>\n")
		fmt.Fprintf(w, "<p><ul>\n")
		for _, file := range files {
			u := r.URL
			q := u.Query()
			q.Set("artifact", strconv.FormatInt(file.GetID(), 10))
			q.Set("name", file.GetName())
			q.Set("size", strconv.FormatInt(file.GetSizeInBytes(), 10))
			u.RawQuery = q.Encode()

			fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", u.String(), file.GetName())
		}
		fmt.Fprintf(w, "</ul></p>\n")
	}
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
			StartTime: cmp.Or(r.GetStartedAt().Time, time.Now()),
		}
		if r.CompletedAt != nil {
			run.EndTime = r.CompletedAt.Time
		} else {
			run.EndTime = time.Now()
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
			StartTime: cmp.Or(r.GetRunStartedAt().Time, time.Now()),
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

func compareTimestamp(a, b *github.Timestamp) int {
	if a == nil && b == nil {
		return 0
	}

	if a == nil {
		return 1
	}

	if b == nil {
		return -1
	}

	return a.Compare(b.Time)
}

func buildTree(owner, repo string, end time.Time, root *Node, allJobs []*github.WorkflowJob) {
	root.Children = make([]*Node, 0, len(allJobs))

	byGroup := map[string]*Node{}

	for _, j := range allJobs {
		slices.SortFunc(j.Steps, func(a, b *github.TaskStep) int {
			return compareTimestamp(a.StartedAt, b.StartedAt)
		})

		steps := make([]*Node, 0, len(j.Steps))

		for _, t := range j.Steps {
			task := &Span{
				Name:      t.GetName(),
				StartTime: cmp.Or(t.GetStartedAt().Time, time.Now()),
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
			StartTime: cmp.Or(j.GetStartedAt().Time, time.Now()),
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
		open := ""
		if parent == nil {
			open = " open"
		}
		if node.Span.Flavor == "failure" {
			fmt.Fprintf(w, `<details%s><summary style="font-weight: bold; color: white; background-color: red">%s %s</summary>`, open, node.Span.Name, href)
		} else {
			fmt.Fprintf(w, `<details%s><summary>%s %s</summary>`, open, node.Span.Name, href)
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

func (s *server) renderCoverage(w http.ResponseWriter, r *http.Request, art string) error {
	name := r.URL.Query().Get("name")

	id, err := strconv.ParseInt(art, 10, 64)
	if err != nil {
		return err
	}

	ctx := r.Context()
	uri := r.URL.Query().Get("uri")

	if uri == "" {
		return nil
	}

	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")
	owner, repo := chunks[0], chunks[1]

	url, _, err := s.Client(r).Actions.DownloadArtifact(ctx, owner, repo, id, 3)
	if err != nil {
		return fmt.Errorf("calling DownloadArtifact: %w", err)
	}

	log.Printf("artifact url: %s", url)

	req, err := http.NewRequestWithContext(r.Context(), "GET", url.String(), nil)
	if err != nil {
		return err
	}

	htrdr, err := httpreaderat.New(nil, req, nil)
	if err != nil {
		return err
	}
	bhtrdr := bufra.NewBufReaderAt(htrdr, 1024*1024)

	zr, err := zip.NewReader(bhtrdr, htrdr.Size())
	if err != nil {
		return err
	}

	if file := r.URL.Query().Get("file"); file != "" {
		return s.renderFile(w, r, zr, file)
	}

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	fmt.Fprintf(w, "<h3>Files in %s</h3>\n", name)
	fmt.Fprintf(w, "<p><ul>\n")
	for _, f := range zr.File {
		// TODO: Encode offset and size so we can Range it.
		u := r.URL
		q := u.Query()
		q.Set("file", f.Name)
		u.RawQuery = q.Encode()
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", u.String(), f.Name)
	}
	fmt.Fprintf(w, "</ul></p>\n")
	fmt.Fprint(w, footer)
	return nil
}

func (s *server) renderLogs(w http.ResponseWriter, r *http.Request, art string) error {
	// TODO
	// qsize := r.URL.Get("size")
	// size, err := strconv.ParseInt(qsize, 10, 64)
	// if err != nil {
	// 	return err
	// }

	name := r.URL.Query().Get("name")

	id, err := strconv.ParseInt(art, 10, 64)
	if err != nil {
		return err
	}

	ctx := r.Context()
	uri := r.URL.Query().Get("uri")

	if uri == "" {
		return nil
	}

	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")
	owner, repo := chunks[0], chunks[1]

	url, _, err := s.Client(r).Actions.DownloadArtifact(ctx, owner, repo, id, 3)
	if err != nil {
		return fmt.Errorf("calling DownloadArtifact: %w", err)
	}

	log.Printf("artifact url: %s", url)

	req, err := http.NewRequestWithContext(r.Context(), "GET", url.String(), nil)
	if err != nil {
		return err
	}

	htrdr, err := httpreaderat.New(nil, req, nil)
	if err != nil {
		return err
	}
	bhtrdr := bufra.NewBufReaderAt(htrdr, 1024*1024)

	zr, err := zip.NewReader(bhtrdr, htrdr.Size())
	if err != nil {
		return err
	}

	if file := r.URL.Query().Get("file"); file != "" {
		return s.renderLog(w, r, zr, file)
	}

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	fmt.Fprintf(w, "<h3>Files in %s</h3>\n", name)
	fmt.Fprintf(w, "<p><ul>\n")
	for _, f := range zr.File {
		// TODO: Encode offset and size so we can Range it.
		u := r.URL
		q := u.Query()
		q.Set("file", f.Name)
		u.RawQuery = q.Encode()
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", u.String(), f.Name)
	}
	fmt.Fprintf(w, "</ul></p>\n")
	fmt.Fprint(w, footer)
	return nil
}

func (s *server) renderLog(w http.ResponseWriter, r *http.Request, zr *zip.Reader, file string) error {
	rc, err := zr.Open(file)
	if err != nil {
		return err
	}
	defer rc.Close()

	fmt.Fprint(w, tlogHeader)
	fmt.Fprintf(w, landing, r.URL.Query().Get("uri"))
	fmt.Fprintf(w, "<h3>%s</h3>\n", file)
	if err := s.renderTlog(w, rc); err != nil {
		return err
	}
	fmt.Fprint(w, tlogFooter)
	return nil
}

func (s *server) renderFile(w http.ResponseWriter, r *http.Request, zr *zip.Reader, file string) error {
	rc, err := zr.Open(file)
	if err != nil {
		return err
	}
	defer rc.Close()

	lm := io.LimitReader(rc, 1024*1024)

	w.Header().Set("Content-Security-Policy", "object-src 'none'; base-uri 'none';")
	if _, err := io.Copy(w, lm); err != nil {
		return err
	}

	return nil
}

type line struct {
	when time.Time
	ts   string
	text string
}

func (s *server) renderTlog(w http.ResponseWriter, r io.Reader) error {
	lines := []line{}
	scanner := bufio.NewScanner(r)

	start := time.Unix(1<<62, 0)
	end := time.Unix(0, 0)

	for scanner.Scan() {
		in := scanner.Text()
		before, after, ok := strings.Cut(in, " ")
		if !ok {
			log.Printf("no space in %q", in)
			continue
		}

		ts := strings.TrimPrefix(before, "time=")

		when, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			log.Printf("parsing timestamp %q: %v", ts, err)
			continue
		}

		if when.Before(start) {
			start = when
		}
		if when.After(end) {
			end = when
		}

		lines = append(lines, line{
			when: when,
			ts:   before,
			text: after,
		})
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	total := end.Sub(start)

	for _, l := range lines {
		left := l.when.Sub(start)
		leftpad := float64(left) / float64(total)
		fmt.Fprintf(w, `<div>`)
		fmt.Fprintf(w, `<span style="background: linear-gradient(90deg, #EEEEEE %f%%, #FFFFFF %f%%);">%s %s</span>`, 100.0*leftpad, 100.0*leftpad, l.ts, l.text)
		fmt.Fprintf(w, "</div>\n")
	}

	return nil
}

const tlogHeader = `
<html>
    <head>
        <title>gha.dag.dev</title>
        <style>
        span {
          display: block;
          white-space: nowrap;
        }
        body {
        	display: block;
					font-family: monospace;
					width: 100%;
					margin: 0px;
        }
        </style>
    </head>
    <body>`

const tlogFooter = `
    </body>
</html>
`

func (s *server) renderTrot(w http.ResponseWriter, r *http.Request, art string) error {
	id, err := strconv.ParseInt(art, 10, 64)
	if err != nil {
		return err
	}

	ctx := r.Context()
	uri := r.URL.Query().Get("uri")

	if uri == "" {
		return nil
	}

	_, after, ok := strings.Cut(uri, "github.com/")
	if !ok {
		return fmt.Errorf("what is this: %q", uri)
	}
	chunks := strings.Split(after, "/")
	owner, repo := chunks[0], chunks[1]

	url, _, err := s.Client(r).Actions.DownloadArtifact(ctx, owner, repo, id, 3)
	if err != nil {
		return fmt.Errorf("calling DownloadArtifact: %w", err)
	}

	log.Printf("artifact url: %s", url)

	resp, err := http.Get(url.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("got status: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	br := bytes.NewReader(b)

	zr, err := zip.NewReader(br, int64(len(b)))
	if err != nil {
		return err
	}

	file, err := zr.Open("trace.json")
	if err != nil {
		return err
	}

	fmt.Fprint(w, header)
	fmt.Fprintf(w, landing, uri)
	if err := trotMain(w, file); err != nil {
		return err
	}
	fmt.Fprint(w, footer)

	return nil
}

func trotMain(w io.Writer, r io.Reader) error {
	spans := map[string]*TrotSpan{}
	children := map[string][]*TrotSpan{}

	dec := json.NewDecoder(r)
	for {
		var span TrotSpan
		if err := dec.Decode(&span); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		spans[span.SpanContext.SpanID] = &span

		kids, ok := children[span.Parent.SpanID]
		if !ok {
			kids = []*TrotSpan{}
		}
		kids = append(kids, &span)
		children[span.Parent.SpanID] = kids
	}

	missing := map[string]struct{}{}

	for parent := range children {
		if _, ok := spans[parent]; !ok {
			missing[parent] = struct{}{}
		}
	}
	for missed := range missing {
		log.Printf("missing %q", missed)
	}

	// TODO: This feels not right.
	rootSpans, ok := children["0000000000000000"]
	if !ok {
		log.Printf("no root")

		for missed := range missing {
			root := &TrotNode{
				Span: &TrotSpan{
					Name: "Missing span",
					SpanContext: TrotSpanContext{
						SpanID: missed,
					},
				},
			}

			buildTrot(root, children, spans)

			trotWriteSpan(w, nil, root)
		}
	}

	for _, rootSpan := range rootSpans {
		root := &TrotNode{
			Span: rootSpan,
		}

		buildTrot(root, children, spans)

		trotWriteSpan(w, nil, root)
	}
	return nil
}

func buildTrot(root *TrotNode, children map[string][]*TrotSpan, spans map[string]*TrotSpan) {
	kids, ok := children[root.Span.SpanContext.SpanID]
	if !ok {
		return
	}

	root.Children = make([]*TrotNode, len(kids))
	for i, kid := range kids {
		node := &TrotNode{
			Span: kid,
		}
		buildTrot(node, children, spans)
		root.Children[i] = node
	}

	slices.SortFunc(root.Children, func(a, b *TrotNode) int {
		return a.Span.StartTime.Compare(b.Span.StartTime)
	})

	if root.Span.StartTime == root.Span.EndTime {
		root.Span.StartTime = root.Children[0].Span.StartTime

		last := slices.MaxFunc(root.Children, func(a, b *TrotNode) int {
			return a.Span.EndTime.Compare(b.Span.EndTime)
		})
		root.Span.EndTime = last.Span.EndTime
	}
}

func trotWriteSpan(w io.Writer, parent, node *TrotNode) {
	if parent == nil {
		fmt.Fprint(w, `<div>`)
	} else {
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

	if len(node.Children) == 0 {
		fmt.Fprintf(w, `<span>%s %s</span>`, node.Span.Name, dur)
	} else {
		open := ""
		if parent == nil {
			open = " open"
		}
		fmt.Fprintf(w, `<details%s><summary>%s %s</summary>`, open, node.Span.Name, dur)
		for _, child := range node.Children {
			trotWriteSpan(w, node, child)
		}
		fmt.Fprint(w, `</details>`)
	}
	fmt.Fprintln(w, "</div>")
}

const trotHeader = `
<html>
<head>
<title>trot</title>
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
	width: 100%;
	margin: 0px;
}
div.parent:hover {
	outline: 1.5px solid lightgrey;
}
</style>
</head>
<body>`

const trotFooter = `
    </body>
</html>
`

type TrotNode struct {
	Span     *TrotSpan
	Children []*TrotNode
}

type TrotSpanContext struct {
	TraceID    string `json:"TraceID"`
	SpanID     string `json:"SpanID"`
	TraceFlags string `json:"TraceFlags"`
	TraceState string `json:"TraceState"`
	Remote     bool   `json:"Remote"`
}

// Thank you mholt.
type TrotSpan struct {
	Name        string          `json:"Name"`
	SpanContext TrotSpanContext `json:"SpanContext"`
	Parent      struct {
		TraceID    string `json:"TraceID"`
		SpanID     string `json:"SpanID"`
		TraceFlags string `json:"TraceFlags"`
		TraceState string `json:"TraceState"`
		Remote     bool   `json:"Remote"`
	} `json:"Parent"`
	SpanKind   int       `json:"SpanKind"`
	StartTime  time.Time `json:"StartTime"`
	EndTime    time.Time `json:"EndTime"`
	Attributes any       `json:"Attributes"`
	Events     any       `json:"Events"`
	Links      any       `json:"Links"`
	Status     struct {
		Code        string `json:"Code"`
		Description string `json:"Description"`
	} `json:"Status"`
	DroppedAttributes int `json:"DroppedAttributes"`
	DroppedEvents     int `json:"DroppedEvents"`
	DroppedLinks      int `json:"DroppedLinks"`
	ChildSpanCount    int `json:"ChildSpanCount"`
	Resource          []struct {
		Key   string `json:"Key"`
		Value struct {
			Type  string `json:"Type"`
			Value string `json:"Value"`
		} `json:"Value"`
	} `json:"Resource"`
	InstrumentationLibrary struct {
		Name      string `json:"Name"`
		Version   string `json:"Version"`
		SchemaURL string `json:"SchemaURL"`
	} `json:"InstrumentationLibrary"`
}
