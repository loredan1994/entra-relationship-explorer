"use client";

import {
  boundedNeighborhood,
  connectedNodes,
  filterRelationships,
  type NodeKind,
  type RelationshipType,
  type RelationshipView,
  type TenantSnapshot,
} from "@entra-explorer/domain";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent } from "react";
import { layoutGraph, NODE_HEIGHT, NODE_WIDTH } from "./graph-layout";
import { PermissionPills } from "./permission-pills";
import { permissionPhrase } from "./permission-utils";
import { RiskBadge } from "./risk-badge";

const kindLabels: Record<NodeKind, { plain: string; microsoft: string }> = {
  application: { plain: "Blueprint", microsoft: "App registration" },
  servicePrincipal: { plain: "Tenant identity", microsoft: "Enterprise application" },
  managedIdentity: { plain: "Managed identity", microsoft: "Service principal" },
  user: { plain: "Person", microsoft: "User" },
  group: { plain: "Group", microsoft: "Group" },
  appRole: { plain: "Application role", microsoft: "App role" },
  directoryRole: { plain: "Administrative role", microsoft: "Directory role" },
  policy: { plain: "Access policy", microsoft: "Conditional Access policy" },
  externalTenant: { plain: "External tenant", microsoft: "Partner tenant" },
};

const relationshipLabels: Record<RelationshipType, string> = {
  INSTANTIATES_AS: "Creates a tenant identity",
  CAN_CALL_AS_APP: "Can call as an app",
  CAN_CALL_DELEGATED: "Can call with a signed-in person",
  ASSIGNED_TO: "Assigned to use",
  EXPOSES_APP_ROLE: "Exposes app role",
  GRANTED_APP_ROLE: "Granted app role",
  MEMBER_OF: "Member of",
  ACTIVE_IN_ROLE: "Active in role",
  ELIGIBLE_FOR_ROLE: "Eligible for role",
  GOVERNED_BY: "Governed by",
  CROSS_TENANT_ACCESS: "Cross-tenant setting",
  OWNS: "Owns",
  OBSERVED_CALL: "Called recently",
};

const MAP_NODE_LIMIT = 15;
const MIN_ZOOM = 0.3;
const MAX_ZOOM = 1.6;

interface SavedFilter {
  id: string;
  label: string;
  query: string;
  nodeKinds: NodeKind[];
}

function arrowVariant(type: RelationshipType): "default" | "app" | "delegated" {
  if (type === "CAN_CALL_AS_APP") return "app";
  if (type === "CAN_CALL_DELEGATED") return "delegated";
  return "default";
}

function explanation(view: RelationshipView) {
  const { edge, source, target } = view;
  if (edge.type === "CAN_CALL_AS_APP") {
    return `${source.label} can call ${target.label} as itself — no signed-in person involved — using ${permissionPhrase(edge.permissions)}.`;
  }
  if (edge.type === "CAN_CALL_DELEGATED") {
    return `${source.label} can call ${target.label} on behalf of a signed-in person using ${permissionPhrase(edge.permissions)}.`;
  }
  if (edge.type === "INSTANTIATES_AS") {
    return `${source.label} is the blueprint that creates the ${target.label} tenant identity.`;
  }
  return `${source.label} ${edge.plainLabel.toLocaleLowerCase()} ${target.label}.`;
}

export function RelationshipExplorer({ snapshot }: { snapshot: TenantSnapshot }) {
  const searchParams = useSearchParams();
  const initialEdgeId = searchParams.get("edge");
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const [selectedKinds, setSelectedKinds] = useState<NodeKind[]>(() =>
    searchParams.getAll("kind").filter((kind): kind is NodeKind => Object.hasOwn(kindLabels, kind)),
  );
  const [viewMode, setViewMode] = useState<"map" | "table">(snapshot.mode === "tenant" ? "table" : "map");
  const allViews = useMemo(() => filterRelationships(snapshot, {}), [snapshot]);
  const initialEdge = allViews.find(({ edge }) => edge.id === initialEdgeId) ??
    allViews.find(({ edge }) => edge.type === "CAN_CALL_AS_APP") ??
    allViews[0];
  const [selectedEdgeId, setSelectedEdgeId] = useState(initialEdge?.edge.id ?? "");
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const storageKey = `entra-explorer-filters:${snapshot.tenant.tenantId}`;
  const neighborhood = useMemo(
    () => focusNodeId ? boundedNeighborhood(snapshot, focusNodeId, MAP_NODE_LIMIT) : null,
    [focusNodeId, snapshot],
  );
  const scopedSnapshot = useMemo<TenantSnapshot>(() => neighborhood ? {
    ...snapshot,
    nodes: neighborhood.nodes,
    edges: neighborhood.edges.map(({ edge }) => edge),
  } : snapshot, [neighborhood, snapshot]);
  const filteredViews = useMemo(
    () => filterRelationships(scopedSnapshot, { query, nodeKinds: selectedKinds }),
    [query, selectedKinds, scopedSnapshot],
  );
  const visibleNodes = useMemo(() => connectedNodes(filteredViews), [filteredViews]);
  const canvasRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ width: 0, height: 0 });
  const [zoom, setZoom] = useState(1);
  const [zoomTouched, setZoomTouched] = useState(false);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [panning, setPanning] = useState(false);
  const panState = useRef({ pointerId: -1, startX: 0, startY: 0, panX: 0, panY: 0 });
  const layout = useMemo(() => layoutGraph(visibleNodes, filteredViews, zoom), [visibleNodes, filteredViews, zoom]);

  // The graph moves by translating the scaled canvas, not by scrolling overflow,
  // so panning works even when the fitted graph is smaller than the viewport.
  // `base` centers the content; `pan` is the user's offset, clamped so at least
  // an 80px sliver of the graph always stays on screen.
  const scaledWidth = layout.width * zoom;
  const scaledHeight = layout.height * zoom;
  const baseX = (viewport.width - scaledWidth) / 2;
  const baseY = (viewport.height - scaledHeight) / 2;
  const panBounds = {
    minX: 80 - scaledWidth - baseX,
    maxX: viewport.width - 80 - baseX,
    minY: 80 - scaledHeight - baseY,
    maxY: viewport.height - 80 - baseY,
  };
  const panBoundsRef = useRef(panBounds);
  panBoundsRef.current = panBounds;

  useEffect(() => {
    const element = canvasRef.current;
    if (!element) return;
    // Ignore zero-sized measurements: a tab rendered while hidden reports 0×0,
    // and adopting that would mis-fit the graph. Re-measure on reveal instead.
    const measure = () => {
      if (element.clientWidth > 0 && element.clientHeight > 0) {
        setViewport({ width: element.clientWidth, height: element.clientHeight });
      }
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    document.addEventListener("visibilitychange", measure);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", measure);
    };
  }, [viewMode]);

  const fitZoom = useMemo(() => {
    if (!viewport.width || !viewport.height || !layout.width || !layout.height) return 1;
    const fit = Math.floor(Math.min(viewport.width / layout.width, viewport.height / layout.height) * 100) / 100;
    return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, fit));
  }, [viewport, layout]);

  const changeZoom = useCallback(
    (delta: number) => {
      setZoomTouched(true);
      setZoom((current) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Number((current + delta).toFixed(2)))));
    },
    [],
  );
  const selectedView = filteredViews.find(({ edge }) => edge.id === selectedEdgeId) ?? filteredViews[0];
  const unresolvedCount = filteredViews.filter(({ edge }) => edge.evidence.completeness === "unresolved").length;

  // Every new layout starts fitted to the viewport (never enlarged past 100%) so
  // the whole graph is visible at once. Connection labels render at constant
  // screen size regardless of zoom, so fitting never shrinks a control below an
  // accessible target size. Manual zooming takes over until the layout changes.
  useEffect(() => {
    setZoomTouched(false);
  }, [visibleNodes, filteredViews]);

  useEffect(() => {
    if (!zoomTouched) {
      setZoom(Math.min(1, fitZoom));
      setPan({ x: 0, y: 0 });
    }
  }, [fitZoom, zoomTouched]);

  // Scroll pans the graph; ctrl/cmd + scroll (also trackpad pinch) zooms. Needs
  // a non-passive native listener because React's delegated wheel handler
  // cannot preventDefault.
  useEffect(() => {
    const element = canvasRef.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      if (event.ctrlKey || event.metaKey) {
        changeZoom(event.deltaY > 0 ? -0.1 : 0.1);
        return;
      }
      const bounds = panBoundsRef.current;
      setPan((current) => ({
        x: Math.min(bounds.maxX, Math.max(bounds.minX, current.x - event.deltaX)),
        y: Math.min(bounds.maxY, Math.max(bounds.minY, current.y - event.deltaY)),
      }));
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [changeZoom, viewMode]);

  function beginPan(event: ReactPointerEvent<HTMLDivElement>) {
    if ((event.target as HTMLElement).closest("button")) return;
    const element = canvasRef.current;
    if (!element) return;
    panState.current = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, panX: pan.x, panY: pan.y };
    element.setPointerCapture(event.pointerId);
    setPanning(true);
  }

  function movePan(event: ReactPointerEvent<HTMLDivElement>) {
    if (!panning || event.pointerId !== panState.current.pointerId) return;
    const bounds = panBoundsRef.current;
    setPan({
      x: Math.min(bounds.maxX, Math.max(bounds.minX, panState.current.panX + (event.clientX - panState.current.startX))),
      y: Math.min(bounds.maxY, Math.max(bounds.minY, panState.current.panY + (event.clientY - panState.current.startY))),
    });
  }

  function endPan(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.pointerId !== panState.current.pointerId) return;
    setPanning(false);
  }

  useEffect(() => {
    try {
      const parsed = JSON.parse(window.localStorage.getItem(storageKey) ?? "[]") as unknown;
      if (!Array.isArray(parsed)) return;
      setSavedFilters(parsed.slice(0, 20).flatMap((item) => {
        if (!item || typeof item !== "object") return [];
        const value = item as Partial<SavedFilter>;
        const kinds = Array.isArray(value.nodeKinds) ? value.nodeKinds.filter((kind): kind is NodeKind => Object.hasOwn(kindLabels, String(kind))) : [];
        if (typeof value.id !== "string" || typeof value.label !== "string" || typeof value.query !== "string") return [];
        return [{ id: value.id.slice(0, 100), label: value.label.slice(0, 80), query: value.query.slice(0, 200), nodeKinds: kinds }];
      }));
    } catch {
      setSavedFilters([]);
    }
  }, [storageKey]);

  function toggleKind(kind: NodeKind) {
    setSelectedKinds((current) =>
      current.includes(kind) ? current.filter((item) => item !== kind) : [...current, kind],
    );
  }

  function selectNode(nodeId: string) {
    const connection = filteredViews.find(({ source, target }) => source.id === nodeId || target.id === nodeId);
    if (connection) setSelectedEdgeId(connection.edge.id);
    setFocusNodeId(nodeId);
  }

  function showMap() {
    if (!focusNodeId && snapshot.nodes.length > MAP_NODE_LIMIT) setFocusNodeId(selectedView?.source.id ?? snapshot.nodes[0]?.id ?? null);
    setViewMode("map");
  }

  function persistFilters(next: SavedFilter[]) {
    setSavedFilters(next);
    window.localStorage.setItem(storageKey, JSON.stringify(next));
  }

  function saveFilter() {
    const label = query.trim() ? `Search: ${query.trim().slice(0, 60)}` : selectedKinds.length ? selectedKinds.map((kind) => kindLabels[kind].plain).join(" + ") : "All relationships";
    const next = [{ id: crypto.randomUUID(), label, query: query.slice(0, 200), nodeKinds: selectedKinds }, ...savedFilters].slice(0, 20);
    persistFilters(next);
  }

  return (
    <div className="explorer-layout">
      <aside className="filter-rail" aria-label="Relationship filters">
        <div className="filter-heading">
          <div>
            <p className="eyebrow">Explore</p>
            <h1>Relationship map</h1>
          </div>
          <span title={snapshot.mode === "fixture" ? "All records are synthetic sample data" : "Encrypted read-only snapshot of your tenant"}>{snapshot.mode === "fixture" ? "Sample data" : "Live tenant"}</span>
        </div>

        <label className="map-search">
          <span>Search the map</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name or permission" />
        </label>

        <fieldset className="filter-group">
          <legend>Object type</legend>
          {(Object.entries(kindLabels) as [NodeKind, (typeof kindLabels)[NodeKind]][]).map(([kind, labels]) => {
            const count = snapshot.nodes.filter((node) => node.kind === kind).length;
            return (
              <label key={kind}>
                <input type="checkbox" checked={selectedKinds.includes(kind)} onChange={() => toggleKind(kind)} />
                <span>
                  {labels.plain}
                  <small>{labels.microsoft}</small>
                </span>
                <em>{count}</em>
              </label>
            );
          })}
        </fieldset>

        <section className="saved-filters" aria-label="Saved filters">
          <div><h2>Saved filters</h2><button className="text-button" type="button" onClick={saveFilter}>Save current</button></div>
          <p>Stored only in this browser.</p>
          {savedFilters.length === 0 ? <small>No saved filters yet.</small> : savedFilters.map((filter) => <div className="saved-filter" key={filter.id}><button type="button" onClick={() => { setQuery(filter.query); setSelectedKinds(filter.nodeKinds); }}>{filter.label}</button><button type="button" aria-label={`Remove saved filter ${filter.label}`} onClick={() => persistFilters(savedFilters.filter((item) => item.id !== filter.id))}>×</button></div>)}
        </section>

        <div className="filter-group filter-summary">
          <h2>Visible scope</h2>
          <p>
            <strong>{visibleNodes.length}</strong> objects
          </p>
          <p>
            <strong>{filteredViews.length}</strong> connections
          </p>
          {focusNodeId ? <button className="text-button" type="button" onClick={() => { setFocusNodeId(null); if (snapshot.nodes.length > MAP_NODE_LIMIT) setViewMode("table"); }}>Clear one-hop focus</button> : null}
        </div>

        <div className="legend">
          <h2>Connection meaning</h2>
          <p><i className="line-solid" /> Configured access</p>
          <p><i className="line-dashed" /> Assignment or ownership</p>
          <p><i className="line-dotted" /> Blueprint match</p>
          <p className="legend-note">Activity is not collected in this read-only phase.</p>
        </div>

        {(query || selectedKinds.length > 0) && (
          <button className="button button-secondary button-full" onClick={() => { setQuery(""); setSelectedKinds([]); }}>
            Clear filters
          </button>
        )}
      </aside>

      <section className="map-workspace" aria-label="Relationship results">
        <div className="map-toolbar">
          <div className="segmented-control" aria-label="Result presentation">
            <button className={viewMode === "map" ? "active" : ""} aria-pressed={viewMode === "map"} onClick={showMap}>Map</button>
            <button className={viewMode === "table" ? "active" : ""} aria-pressed={viewMode === "table"} onClick={() => setViewMode("table")}>Table</button>
          </div>
          {viewMode === "map" ? (
            <div className="zoom-control" role="group" aria-label="Map zoom">
              <button type="button" onClick={() => changeZoom(-0.15)} disabled={zoom <= MIN_ZOOM} aria-label="Zoom out">−</button>
              <span aria-live="polite">{Math.round(zoom * 100)}%</span>
              <button type="button" onClick={() => changeZoom(0.15)} disabled={zoom >= MAX_ZOOM} aria-label="Zoom in">+</button>
              <button type="button" className="zoom-fit" onClick={() => { setZoomTouched(true); setZoom(fitZoom); }}>Fit</button>
            </div>
          ) : null}
          <div className="configured-key">
            <span aria-hidden="true" />
            Configured directory facts · no observed activity
          </div>
          {viewMode === "map" ? <span className="map-hint">Drag or scroll to pan · ⌘/Ctrl + scroll to zoom</span> : null}
        </div>

        {focusNodeId ? <div className="scope-banner"><strong>One-hop view.</strong> Select an object to expand its direct relationships.{neighborhood?.truncated ? ` Limited to ${MAP_NODE_LIMIT} objects; use the table for the complete result.` : ""}</div> : null}
        {unresolvedCount > 0 ? <div className="unresolved-banner" role="status"><strong>{unresolvedCount} unresolved {unresolvedCount === 1 ? "relationship" : "relationships"}.</strong> The source scan was incomplete; inspect evidence before drawing conclusions.</div> : null}

        {filteredViews.length === 0 ? (
          <div className="map-empty">
            <span aria-hidden="true">⌕</span>
            <h2>No relationships match</h2>
            <p>The current snapshot contains data, but the search or object filter hides it.</p>
            <button className="button button-secondary" onClick={() => { setQuery(""); setSelectedKinds([]); }}>Clear filters</button>
          </div>
        ) : viewMode === "map" ? (
          <div
            className={`relationship-canvas ${panning ? "panning" : ""}`}
            ref={canvasRef}
            role="group"
            aria-label={`${visibleNodes.length} objects and ${filteredViews.length} configured connections`}
            onPointerDown={beginPan}
            onPointerMove={movePan}
            onPointerUp={endPan}
            onPointerCancel={endPan}
          >
            <div className="canvas-scaler" style={{ width: scaledWidth, height: scaledHeight, transform: `translate(${Math.round(baseX + pan.x)}px, ${Math.round(baseY + pan.y)}px)` }}>
            <div className="canvas-inner" style={{ width: layout.width, height: layout.height, transform: `scale(${zoom})`, "--zoom": zoom } as CSSProperties}>
              <svg
                className="edge-lines"
                width={layout.width}
                height={layout.height}
                viewBox={`0 0 ${layout.width} ${layout.height}`}
                aria-hidden="true"
              >
                <defs>
                  {["default", "app", "delegated"].map((variant) => (
                    <marker
                      key={variant}
                      id={`arrow-${variant}`}
                      className={`arrow-${variant}`}
                      viewBox="0 0 10 10"
                      refX="9"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" />
                    </marker>
                  ))}
                </defs>
                {layout.edges.map(({ view, path }) => (
                  <path
                    key={view.edge.id}
                    className={`edge-line edge-${view.edge.type.toLocaleLowerCase()} ${selectedView?.edge.id === view.edge.id ? "edge-selected" : ""}`}
                    d={path}
                    fill="none"
                    markerEnd={`url(#arrow-${arrowVariant(view.edge.type)})`}
                  />
                ))}
              </svg>

              {layout.edges.map(({ view, label }) => (
                <button
                  key={view.edge.id}
                  className={`connection-label ${selectedView?.edge.id === view.edge.id ? "selected" : ""}`}
                  style={{ left: label.x, top: label.y, width: label.width, transform: `translate(-50%, -50%) scale(${(1 / zoom).toFixed(3)})` }}
                  onClick={() => setSelectedEdgeId(view.edge.id)}
                  title={`${view.source.label} ${view.edge.plainLabel} ${view.target.label}: ${label.full}`}
                  aria-label={`${view.source.label} ${view.edge.plainLabel} ${view.target.label}: ${label.full}. Configured relationship.`}
                >
                  {label.text}
                </button>
              ))}

              {layout.nodes.map(({ node, x, y }) => (
                <button
                  key={node.id}
                  className={`entity-node node-${node.kind} ${selectedView && (selectedView.source.id === node.id || selectedView.target.id === node.id) ? "connected" : ""}`}
                  style={{ left: x, top: y, width: NODE_WIDTH, height: NODE_HEIGHT }}
                  onClick={() => selectNode(node.id)}
                  title={node.label}
                  aria-label={`${node.label}, ${kindLabels[node.kind].plain}, risk ${node.risk.level}`}
                >
                  <span>{kindLabels[node.kind].plain}</span>
                  <strong>{node.label}</strong>
                  <small>{node.kind === "servicePrincipal" ? "Enterprise application" : kindLabels[node.kind].microsoft}</small>
                </button>
              ))}
            </div>
            </div>
          </div>
        ) : (
          <RelationshipTable views={filteredViews} selectedEdgeId={selectedView?.edge.id} onSelect={setSelectedEdgeId} />
        )}
      </section>

      <EvidenceInspector view={selectedView} />
    </div>
  );
}

function RelationshipTable({
  views,
  selectedEdgeId,
  onSelect,
}: {
  views: RelationshipView[];
  selectedEdgeId?: string;
  onSelect: (edgeId: string) => void;
}) {
  return (
    <div className="relationship-table-wrap">
      <table className="relationship-table">
        <caption className="sr-only">Configured relationships equivalent to the map</caption>
        <thead>
          <tr>
            <th>Source</th>
            <th>Relationship</th>
            <th>Target</th>
            <th>Permission</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {views.map(({ edge, source, target }) => (
            <tr key={edge.id} className={selectedEdgeId === edge.id ? "selected" : ""}>
              <td><strong>{source.label}</strong><small>{kindLabels[source.kind].plain}</small></td>
              <td>{relationshipLabels[edge.type]}<small>Configured</small></td>
              <td><strong>{target.label}</strong><small>{kindLabels[target.kind].plain}</small></td>
              <td className="mono">{edge.permissions.length > 4 ? `${edge.permissions.slice(0, 4).join(", ")} +${edge.permissions.length - 4} more` : edge.permissions.join(", ") || "—"}</td>
              <td><button className="text-button" onClick={() => onSelect(edge.id)}>Inspect</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvidenceInspector({ view }: { view?: RelationshipView }) {
  if (!view) {
    return (
      <aside className="evidence-inspector">
        <div className="map-empty compact"><h2>No evidence selected</h2></div>
      </aside>
    );
  }

  const { edge, source, target } = view;
  return (
    <aside className="evidence-inspector" aria-label="Selected relationship evidence" aria-live="polite">
      <div className="inspector-header">
        <p className="eyebrow">Why this line exists</p>
        <h2>{edge.plainLabel}</h2>
        <span className="evidence-status"><i aria-hidden="true" /> Configured relationship</span>
      </div>

      <div className="plain-explanation">
        <p>{explanation(view)}</p>
        <p className="trust-note"><strong>Configured access.</strong> This does not prove recent use.</p>
      </div>

      {edge.permissions.length > 0 ? (
        <section className="inspector-section">
          <h3>Permission values{edge.permissions.length > 1 ? ` (${edge.permissions.length})` : ""}</h3>
          <PermissionPills permissions={edge.permissions} limit={6} />
        </section>
      ) : null}

      <section className="inspector-section entity-pair">
        <h3>Connected objects</h3>
        {[source, target].map((node, index) => (
          <div key={node.id}>
            <small>{index === 0 ? "From" : "To"} · {kindLabels[node.kind].plain}</small>
            <strong>{node.label}</strong>
            <code>{node.id}</code>
            {(node.kind === "application" || node.kind === "servicePrincipal") ? (
              <Link href={`/applications/${node.id}`}>Open application detail</Link>
            ) : null}
          </div>
        ))}
      </section>

      <section className="inspector-section evidence-facts">
        <h3>Source evidence</h3>
        <dl>
          <div><dt>Relationship type</dt><dd><code>{edge.type}</code></dd></div>
          <div><dt>Source endpoint</dt><dd><code>{edge.evidence.sourceEndpoint}</code></dd></div>
          <div><dt>Source record IDs</dt><dd>{edge.evidence.sourceRecordIds.map((id) => <code key={id}>{id}</code>)}</dd></div>
          <div><dt>Collected</dt><dd>{new Date(edge.evidence.scannedAt).toLocaleString("en", { timeZone: "UTC", timeZoneName: "short" })}</dd></div>
          <div><dt>Completeness</dt><dd className="capitalized">{edge.evidence.completeness}</dd></div>
          <div><dt>Observed activity</dt><dd>Not collected</dd></div>
        </dl>
      </section>

      <div className="inspector-footer">
        <RiskBadge level={source.risk.level} reason={source.risk.reason} />
        <p>{source.risk.reason}</p>
      </div>
    </aside>
  );
}
