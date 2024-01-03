package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
	log.Printf("client")

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

func (s *server) handlerE(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	uri := r.URL.Query().Get("uri")

	if uri == "" {
		return nil
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

	opt := &github.ListWorkflowJobsOptions{
		// Filter: "all",
	}

	start := time.Unix(1<<62, 0)
	end := time.Unix(0, 0)

	allJobs := []*github.WorkflowJob{}
	for {
		log.Printf("list workflow job")
		//jobs, resp, err := client.Actions.ListWorkflowJobs(ctx, "chainguard-images", "images", 7291646262, opt)
		//jobs, resp, err := client.Actions.ListWorkflowJobs(ctx, "chainguard-images", "images", 7333592988, opt)

		jobs, resp, err := s.client.Actions.ListWorkflowJobs(ctx, chunks[0], chunks[1], run, opt)
		if err != nil {
			return fmt.Errorf("ListWorkflowJobs: %w", err)
		}
		log.Printf("total %d", jobs.GetTotalCount())
		allJobs = append(allJobs, jobs.Jobs...)
		if resp.NextPage == 0 {
			break
		}
		log.Printf("added %d jobs", len(jobs.Jobs))
		log.Printf("allJobs = %d ", len(allJobs))
		opt.Page = resp.NextPage
		log.Printf("opt.Page = %d", opt.Page)
	}

	slices.SortFunc(allJobs, func(a, b *github.WorkflowJob) int {
		return cmp.Compare(a.StartedAt.UnixMicro(), b.StartedAt.UnixMicro())
	})

	for _, j := range allJobs {
		if j.StartedAt.Before(start) {
			start = j.StartedAt.Time
		}
		if j.CompletedAt.After(end) {
			end = j.CompletedAt.Time
		}
		log.Printf("start=%s, end=%s", start, end)
	}

	root := &Node{
		Span: &Span{
			Name:      uri,
			Href:      uri,
			StartTime: start,
			EndTime:   end,
		},
	}

	buildTree(root, allJobs)

	fmt.Fprint(w, header)
	writeSpan(w, nil, root)
	fmt.Fprint(w, footer)

	return nil
}

type Node struct {
	Span     *Span
	Children []*Node
}

func buildTree(root *Node, allJobs []*github.WorkflowJob) {
	root.Children = make([]*Node, 0, len(allJobs))

	for _, j := range allJobs {
		slices.SortFunc(j.Steps, func(a, b *github.TaskStep) int {
			return a.StartedAt.Compare(b.StartedAt.Time)
		})

		steps := make([]*Node, 0, len(j.Steps))

		for _, t := range j.Steps {
			task := &Span{
				Name:      t.GetName(),
				StartTime: t.StartedAt.Time,
				EndTime:   t.CompletedAt.Time,
			}

			if conc := t.GetConclusion(); conc != "success" {
				task.Flavor = conc
			}

			steps = append(steps, &Node{
				Span: task,
			})
		}

		job := &Span{
			Name:      j.GetName(),
			Href:      j.GetHTMLURL(),
			StartTime: j.StartedAt.Time,
			EndTime:   j.CompletedAt.Time,
		}

		if conc := j.GetConclusion(); conc != "success" {
			job.Flavor = conc
		}

		root.Children = append(root.Children, &Node{
			Span:     job,
			Children: steps,
		})
	}

	slices.SortFunc(root.Children, func(a, b *Node) int {
		return a.Span.StartTime.Compare(b.Span.StartTime)
	})
}

func writeSpan(w io.Writer, parent, node *Node) {
	log.Printf("%q has %d children", node.Span.Name, len(node.Children))
	if parent == nil {
		fmt.Fprint(w, `<div>`)
	} else {
		// TODO
		total := parent.Span.EndTime.Sub(parent.Span.StartTime)
		left := node.Span.StartTime.Sub(parent.Span.StartTime)
		right := parent.Span.EndTime.Sub(node.Span.EndTime)

		log.Printf("%s %s %s", total, left, right)

		leftpad := float64(left) / float64(total)
		rightpad := float64(right) / float64(total)

		log.Printf("%f %f", leftpad, rightpad)
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
		href += " (" + flavor + ")"
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
<title>trace thing</title>
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
	fmt.Fprint(w, header)
	fmt.Fprint(w, landing)
	fmt.Fprint(w, footer)
}

const landing = `
<form action="/trace" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="uri" value="https://github.com/wolfi-dev/os/actions/runs/7390601887"/>
<input type="submit" />
</form>
`

// Thank you mholt.
type Span struct {
	Name      string `json:"Name"`
	Href      string
	Flavor    string
	StartTime time.Time `json:"StartTime"`
	EndTime   time.Time `json:"EndTime"`
}
