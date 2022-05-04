package samples

import "net/http"

func Reader(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}
func main() {
	http.HandleFunc("/", Reader)
	http.ListenAndServe(":8080", nil)
}
