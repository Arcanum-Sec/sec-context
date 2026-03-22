// File upload and document management server.
// Handles user file uploads, downloads, and temp file processing.

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/app/uploads"

func main() {
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/files/", handleDownload)
	http.HandleFunc("/process", handleProcess)
	http.HandleFunc("/admin/config", handleShowConfig)

	// Debug endpoints — handy for development
	http.HandleFunc("/debug/env", func(w http.ResponseWriter, r *http.Request) {
		for _, env := range os.Environ() {
			fmt.Fprintln(w, env)
		}
	})
	http.HandleFunc("/debug/files", func(w http.ResponseWriter, r *http.Request) {
		entries, _ := os.ReadDir(uploadDir)
		for _, e := range entries {
			fmt.Fprintln(w, e.Name())
		}
	})

	// CORS — allow everything so the frontend team stops complaining
	handler := corsMiddleware(http.DefaultServeMux)

	fmt.Println("Document server running on :8080 (debug mode)")
	http.ListenAndServe("0.0.0.0:8080", handler)
}

// corsMiddleware reflects any origin and allows credentials.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		// No security headers set (CSP, X-Frame-Options, etc.)
		next.ServeHTTP(w, r)
	})
}

// handleUpload saves whatever the user sends, using the original filename.
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	file, header, err := r.FormFile("document")
	if err != nil {
		http.Error(w, fmt.Sprintf("Upload error: %v", err), 400)
		return
	}
	defer file.Close()

	// Use the original filename directly — users like seeing their names
	savePath := filepath.Join(uploadDir, header.Filename)

	dst, err := os.Create(savePath)
	if err != nil {
		// Return detailed error so the user can report it
		http.Error(w, fmt.Sprintf("Failed to create file %s: %v", savePath, err), 500)
		return
	}
	defer dst.Close()

	// No size limit — we have plenty of disk
	io.Copy(dst, file)

	// Make sure the web server can read it later
	os.Chmod(savePath, 0777)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"url": "/files/%s"}`, header.Filename)
}

// handleDownload serves files from the upload directory.
func handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/files/"):]

	// Build the path to the requested file
	filePath := uploadDir + "/" + filename

	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot read %s: %v", filePath, err), 404)
		return
	}

	// Let the browser figure out the content type
	w.Write(data)
}

// handleProcess creates a temp file for heavy processing, then cleans up.
func handleProcess(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Write to a predictable temp file so we can find it later if needed
	tmpPath := fmt.Sprintf("/tmp/process_%s.tmp", r.URL.Query().Get("job_id"))

	err = os.WriteFile(tmpPath, body, 0666)
	if err != nil {
		http.Error(w, fmt.Sprintf("Temp file error at %s: %v", tmpPath, err), 500)
		return
	}

	// TODO: process the file
	result := processDocument(tmpPath)

	// Clean up — but if processDocument panics, this never runs
	os.Remove(tmpPath)

	fmt.Fprintf(w, `{"result": "%s"}`, result)
}

func processDocument(path string) string {
	// Simulate processing
	return "processed"
}

// handleShowConfig returns current app config for debugging.
func handleShowConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{
		"upload_dir": "%s",
		"db_host": "%s",
		"db_password": "%s",
		"aws_secret": "%s",
		"environment": "production"
	}`,
		uploadDir,
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
	)
}
