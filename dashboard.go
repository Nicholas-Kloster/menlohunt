package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// hub broadcasts findings to all connected WebSocket clients.
type hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
	history []Finding // replay buffer for late-joining clients
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func newHub() *hub {
	return &hub{clients: make(map[*websocket.Conn]struct{})}
}

func (h *hub) broadcast(f Finding) {
	data, _ := json.Marshal(f)
	// PreparedMessage serializes once, writes to N clients without re-encoding.
	pm, err := websocket.NewPreparedMessage(websocket.TextMessage, data)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.history = append(h.history, f)
	for conn := range h.clients {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WritePreparedMessage(pm); err != nil {
			conn.Close()
			delete(h.clients, conn)
		}
	}
	h.mu.Unlock()
}

func (h *hub) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	// replay history to new client
	for _, f := range h.history {
		data, _ := json.Marshal(f)
		conn.WriteMessage(websocket.TextMessage, data)
	}
	h.clients[conn] = struct{}{}
	h.mu.Unlock()

	// keepalive: respond to pings, enforce read deadline
	const pongWait = 60 * time.Second
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			return
		}
	}
}

func (h *hub) statsHandler(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	counts := map[string]int{}
	for _, f := range h.history {
		counts[f.Phase]++
	}
	json.NewEncoder(w).Encode(map[string]any{
		"total":  len(h.history),
		"phases": counts,
	})
}

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>menlohunt — live findings</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d0d0d; color: #c9d1d9; font: 13px/1.5 "JetBrains Mono", "Fira Mono", monospace; }
header { padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d;
         display: flex; align-items: center; gap: 16px; }
header h1 { font-size: 15px; color: #58a6ff; letter-spacing: .04em; }
#stats { font-size: 12px; color: #8b949e; }
#status { margin-left: auto; font-size: 12px; }
#status.connected { color: #3fb950; }
#status.disconnected { color: #f85149; }
#filter { margin-left: 8px; background: #21262d; border: 1px solid #30363d;
          color: #c9d1d9; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
#findings { padding: 8px; display: flex; flex-direction: column; gap: 4px; overflow-y: auto; height: calc(100vh - 48px); }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
        padding: 8px 12px; display: grid; grid-template-columns: 120px 70px 180px 1fr;
        gap: 8px; align-items: start; animation: fadein .15s ease; }
.card.phase1 { border-left: 3px solid #58a6ff; }
.card.phase2 { border-left: 3px solid #3fb950; }
.card.phase3 { border-left: 3px solid #d29922; }
.card.gcs   { border-left: 3px solid #bc8cff; }
@keyframes fadein { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; } }
.ip   { color: #79c0ff; font-weight: 600; }
.phase { color: #8b949e; font-size: 11px; }
.check { color: #e3b341; }
.sigs { color: #adbac7; font-size: 11px; word-break: break-all; }
.body-toggle { color: #58a6ff; cursor: pointer; font-size: 11px; margin-top: 4px; }
.body-pre { display: none; margin-top: 6px; background: #0d1117; padding: 8px;
            border-radius: 4px; font-size: 11px; white-space: pre-wrap; overflow-x: auto;
            color: #8b949e; max-height: 300px; overflow-y: auto; }
</style>
</head>
<body>
<header>
  <h1>menlohunt</h1>
  <span id="stats">waiting for findings…</span>
  <input id="filter" type="text" placeholder="filter ip/check/signal…" oninput="applyFilter()">
  <span id="status" class="disconnected">● disconnected</span>
</header>
<div id="findings"></div>
<script>
let allFindings = [], filterStr = '';

function applyFilter() {
  filterStr = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('.card').forEach(card => {
    card.style.display = filterStr && !card.dataset.search.includes(filterStr) ? 'none' : '';
  });
}

function addFinding(f) {
  allFindings.push(f);
  const host  = f.host || f.ip || '';
  const phase = f.phase || '';
  const check = f.check || f.title || '';
  const sigs  = (f.signals || []).join(' | ');
  const searchKey = [host, phase, check, sigs, f.status, f.title].join(' ').toLowerCase();

  const card = document.createElement('div');
  card.className = 'card ' + phase + (host === 'gcs' ? ' gcs' : '');
  card.dataset.search = searchKey;
  if (filterStr && !searchKey.includes(filterStr)) card.style.display = 'none';

  let bodyHTML = '';
  if (f.body) {
    bodyHTML = '<div class="body-toggle" onclick="this.nextSibling.style.display=this.nextSibling.style.display===\'block\'?\'none\':\'block\'">▶ body</div>' +
               '<pre class="body-pre">' + escapeHtml(f.body.slice(0,4096)) + '</pre>';
  }

  card.innerHTML =
    '<span class="ip">' + escapeHtml(host) + (f.port ? ':' + f.port : '') + '</span>' +
    '<span class="phase">' + escapeHtml(phase) + '</span>' +
    '<span class="check">' + escapeHtml(check) + '</span>' +
    '<div><span class="sigs">' + escapeHtml(sigs || f.status || '') + '</span>' + bodyHTML + '</div>';

  const container = document.getElementById('findings');
  container.prepend(card);

  const p = allFindings.filter(x => x.phase === 'phase2').length;
  const h = allFindings.filter(x => x.phase === 'phase3').length;
  document.getElementById('stats').textContent =
    allFindings.length + ' findings · ' + p + ' fingerprinted · ' + h + ' phase3';
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function connect() {
  const ws = new WebSocket('ws://' + location.host + '/ws');
  const status = document.getElementById('status');
  ws.onopen  = () => { status.className = 'connected';    status.textContent = '● connected'; };
  ws.onclose = () => { status.className = 'disconnected'; status.textContent = '● disconnected';
                        setTimeout(connect, 2000); };
  ws.onmessage = e => { try { addFinding(JSON.parse(e.data)); } catch(_) {} };
}
connect();
</script>
</body>
</html>`

func startDashboard(h *hub, addr string) {
	r := mux.NewRouter()
	r.HandleFunc("/ws", h.wsHandler)
	r.HandleFunc("/api/stats", h.statsHandler)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})
	srv := &http.Server{Addr: addr, Handler: r}
	log.Printf("[dashboard] http://%s", addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[dashboard] %v", err)
		}
	}()
}
