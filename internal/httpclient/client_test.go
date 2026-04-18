package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientSubmit(t *testing.T) {
	t.Run("GET encodes params into query string", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("got method %s, want GET", r.Method)
			}
			if got := r.URL.Query().Get("q"); got != "hello world" {
				t.Fatalf("got q=%q, want %q", got, "hello world")
			}
			if got := r.Header.Get("User-Agent"); got != userAgent {
				t.Fatalf("got user-agent %q, want %q", got, userAgent)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html>ok</html>"))
		}))
		defer ts.Close()

		client := NewClient(ts.Client())
		result, err := client.Submit(SubmitRequest{
			Method: http.MethodGet,
			URL:    ts.URL,
			Params: map[string]string{"q": "hello world"},
			Ctx:    context.Background(),
		})
		if err != nil {
			t.Fatalf("Submit returned error: %v", err)
		}

		if result.ContentType != "text/html" {
			t.Fatalf("got content type %q, want text/html", result.ContentType)
		}
	})

	t.Run("POST encodes form body and caller can override content type", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("got method %s, want POST", r.Method)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading body: %v", err)
			}
			if got := string(body); got != "input=hello+world" {
				t.Fatalf("got body %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/custom" {
				t.Fatalf("got content-type %q, want override", got)
			}
			if got := r.Header.Get("X-Test"); got != "yes" {
				t.Fatalf("got X-Test %q, want yes", got)
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		}))
		defer ts.Close()

		client := NewClient(ts.Client())
		_, err := client.Submit(SubmitRequest{
			Method: http.MethodPost,
			URL:    ts.URL,
			Params: map[string]string{"input": "hello world"},
			Headers: map[string]string{
				"Content-Type": "application/custom",
				"X-Test":       "yes",
			},
			Ctx: context.Background(),
		})
		if err != nil {
			t.Fatalf("Submit returned error: %v", err)
		}
	})

	t.Run("captures final URL after redirect", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/final", http.StatusFound)
		})
		mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("done"))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		client := NewClient(ts.Client())
		result, err := client.Submit(SubmitRequest{
			Method: http.MethodGet,
			URL:    ts.URL + "/start",
			Ctx:    context.Background(),
		})
		if err != nil {
			t.Fatalf("Submit returned error: %v", err)
		}

		if result.FinalURL != ts.URL+"/final" {
			t.Fatalf("got final URL %q, want %q", result.FinalURL, ts.URL+"/final")
		}
	})

	t.Run("cancelled context propagates cleanly", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("slow"))
		}))
		defer ts.Close()

		client := NewClient(ts.Client())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := client.Submit(SubmitRequest{
			Method: http.MethodGet,
			URL:    ts.URL,
			Ctx:    ctx,
		})
		if err == nil {
			t.Fatal("expected context cancellation error")
		}
		if !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("got error %v, want context canceled", err)
		}
	})
}
