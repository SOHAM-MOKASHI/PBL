/**
 * useWebSocket.js — Custom hook for CSOC WebSocket connection
 */
import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://localhost:8000/ws/alerts';
const MAX_LOGS = 150;
const MAX_ALERTS = 80;
const MAX_TIMELINE = 60;

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [metrics, setMetrics] = useState({
    total_ingested: 0,
    total_dropped: 0,
    total_scored: 0,
    total_alerts: 0,
    active_threats: 0,
  });
  const [lastCritical, setLastCritical] = useState(null);

  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const reconnectAttempt = useRef(0);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      reconnectAttempt.current = 0;
      console.log('[CSOC] WebSocket connected');
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        if (msg.type === 'ping') return;

        if (msg.type === 'init') {
          if (msg.recent_logs?.length) {
            setLogs(msg.recent_logs.slice(0, MAX_LOGS));
          }
          if (msg.alerts?.length) {
            setAlerts(msg.alerts.slice(0, MAX_ALERTS));
          }
          if (msg.timeline?.length) {
            setTimeline(msg.timeline.slice(-MAX_TIMELINE));
          }
          if (msg.metrics) setMetrics(msg.metrics);
          return;
        }

        if (msg.type === 'log') {
          const { data, metrics: m } = msg;

          // Update logs (prepend newest)
          setLogs(prev => {
            const next = [data, ...prev];
            return next.length > MAX_LOGS ? next.slice(0, MAX_LOGS) : next;
          });

          // High severity → alerts list
          if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
            setAlerts(prev => {
              const next = [data, ...prev];
              return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
            });
            if (data.severity === 'CRITICAL') {
              setLastCritical(data);
            }
          }

          // Timeline
          setTimeline(prev => {
            const ts = Math.floor(data.timestamp);
            const last = prev[prev.length - 1];
            if (last && last.ts === ts) {
              const updated = [...prev];
              const bucket = { ...updated[updated.length - 1] };
              bucket.avg_score = parseFloat(
                ((bucket.avg_score * bucket.count + data.threat_score) / (bucket.count + 1)).toFixed(1)
              );
              bucket.max_score = Math.max(bucket.max_score, data.threat_score);
              bucket.count++;
              updated[updated.length - 1] = bucket;
              return updated;
            } else {
              const newBucket = {
                ts,
                time: new Date(data.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false }),
                avg_score: data.threat_score,
                max_score: data.threat_score,
                count: 1,
              };
              const next = [...prev, newBucket];
              return next.length > MAX_TIMELINE ? next.slice(-MAX_TIMELINE) : next;
            }
          });

          // Metrics
          if (m) setMetrics(m);
        }
      } catch (e) {
        console.error('[CSOC] Parse error:', e);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      const delay = Math.min(1000 * 2 ** reconnectAttempt.current, 10000);
      reconnectAttempt.current++;
      console.log(`[CSOC] Reconnecting in ${delay}ms...`);
      reconnectTimer.current = setTimeout(connect, delay);
    };

    ws.onerror = (err) => {
      console.error('[CSOC] WS error', err);
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { connected, logs, alerts, timeline, metrics, lastCritical };
}
