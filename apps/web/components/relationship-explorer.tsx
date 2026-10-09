"use client";

import {
  boundedNeighborhood,
  connectedNodes,
  filterRelationships,
  type NodeKind,
  type RelationshipType,
  type RelationshipEdge,
  type RelationshipView,
  type TenantSnapshot,
} from "@entra-explorer/domain";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent, type Ref } from "react";
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
  device: { plain: "Device", microsoft: "Directory device" },
  administrativeUnit: { plain: "Administrative unit", microsoft: "Directory scope" },
  federatedCredential: { plain: "Federated credential", microsoft: "Federated identity credential" },
  appRole: { plain: "Application role", microsoft: "App role" },
  directoryRole: { plain: "Administrative role", microsoft: "Directory role" },
  policy: { plain: "Access policy", microsoft: "Microsoft policy" },
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
  IN_ADMINISTRATIVE_UNIT: "In administrative unit",
  FEDERATES_AS: "Can federate as",
  ACTIVE_IN_ROLE: "Active in role",
  ELIGIBLE_FOR_ROLE: "Eligible for role",
  GOVERNED_BY: "Governed by",
  ASSIGNS_CONSENT_POLICY: "Assigns consent policy",
  CROSS_TENANT_ACCESS: "Cross-tenant setting",
  OWNS: "Owns",
  OBSERVED_CALL: "Successful sign-in to resource",
};

const MAP_NODE_LIMIT = 15;
const TABLE_PAGE_SIZE = 50;
const MIN_ZOOM = 0.2;
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

function evidenceLabel(edge: RelationshipEdge) {
  if (edge.evidence.configured && edge.evidence.observed) return "Configured and observed";
  if (edge.evidence.configured) return "Configured";
  return edge.evidence.observed ? "Observed sign-in" : "Evidence incomplete";
}

export function RelationshipExplorer({ snapshot }: { snapshot: TenantSnapshot }) {
  const searchParams = useSearchParams();
  // Next preserves client state on query-only navigation. A new URL or snapshot
  // starts a new investigation; local filter edits remain local until then.
  return <RelationshipWorkspace key={JSON.stringify([snapshot.tenant.tenantId, snapshot.id, searchParams.toString()])} snapshot={snapshot} initialQuery={searchParams.get("q") ?? ""} initialKinds={searchParams.getAll("kind").filter((kind): kind is NodeKind => Object.hasOwn(kindLabels, kind))} initialEdgeId={searchParams.get("edge")} />;
}

function RelationshipWorkspace({ snapshot, initialQuery, initialKinds, initialEdgeId }: { snapshot: TenantSnapshot; initialQuery: string; initialKinds: NodeKind[]; initialEdgeId: string | null }) {
  const [query, setQuery] = useState(initialQuery);
  const [selectedKinds, setSelectedKinds] = useState<NodeKind[]>(initialKinds);
  const [viewMode, setViewMode] = useState<"map" | "table">(snapshot.mode === "tenant" || snapshot.nodes.length > MAP_NODE_LIMIT ? "table" : "map");
  const allViews = useMemo(() => filterRelationships(snapshot, {}), [snapshot]);
  const initialEdge = allViews.find(({ edge }) => edge.id === initialEdgeId) ??
    allViews.find(({ edge }) => edge.type === "CAN_CALL_AS_APP") ??
    allViews[0];
  const [selectedEdgeId, setSelectedEdgeId] = useState(initialEdge?.edge.id ?? "");
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [filterStorageStatus, setFilterStorageStatus] = useState("");
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false);
  const [filtersReady, setFiltersReady] = useState(false);
  const inspectorRef = useRef<HTMLElement>(null);
  const resultsRef = useRef<HTMLElement>(null);
  const inspectionTrigger = useRef<{ element: HTMLElement; edgeId: string } | null>(null);
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
  // An incoming Inspect link is also an explicit inspection request. Do not
  // focus a fallback relationship when its ID is absent, stale or filtered out.
  const [inspectionRequest, setInspectionRequest] = useState(() => filteredViews.some(({ edge }) => edge.id === initialEdgeId) ? 1 : 0);
  const visibleNodes = useMemo(() => connectedNodes(filteredViews), [filteredViews]);
  const hasRelationships = filteredViews.length > 0;
  const canvasRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ width: 0, height: 0 });
  const [zoom, setZoom] = useState(1);
  const [zoomTouched, setZoomTouched] = useState(false);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [panning, setPanning] = useState(false);
  const panState = useRef({ pointerId: -1, startX: 0, startY: 0, panX: 0, panY: 0 });
  const layout = useMemo(() => viewMode === "map" ? layoutGraph(visibleNodes, filteredViews, zoom) : { width: 0, height: 0, nodes: [], edges: [] }, [viewMode, visibleNodes, filteredViews, zoom]);
  const configuredCount = filteredViews.filter(({ edge }) => edge.evidence.configured).length;
  const observedCount = filteredViews.filter(({ edge }) => edge.evidence.observed).length;
  const incompleteCount = filteredViews.filter(({ edge }) => !edge.evidence.configured && !edge.evidence.observed).length;

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

  // Streamed HTML can arrive before this component's event handlers. Exposing
  // an enabled toggle then would silently discard a visitor's first click.
  useEffect(() => { setFiltersReady(true); }, []);

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
  }, [viewMode, hasRelationships]);

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

  useEffect(() => {
    if (!inspectionRequest) return;
    const inspector = inspectorRef.current;
    if (!inspector) return;
    inspector.scrollTop = 0;
    inspector.focus({ preventScroll: true });
    inspector.scrollIntoView({ block: "start", inline: "nearest" });
  }, [inspectionRequest]);

  function inspectRelationship(edgeId: string, trigger: HTMLElement) {
    inspectionTrigger.current = { element: trigger, edgeId };
    setSelectedEdgeId(edgeId);
    // Also reveal an already-selected relationship when Inspect is clicked again.
    setInspectionRequest((request) => request + 1);
  }

  function returnToRelationship() {
    const trigger = inspectionTrigger.current;
    const currentControl = [...(resultsRef.current?.querySelectorAll<HTMLElement>('[aria-controls="relationship-evidence"][aria-pressed="true"]') ?? [])].find(element => element.getClientRects().length > 0);
    const target = trigger?.edgeId === selectedView?.edge.id && trigger?.element.isConnected && trigger.element.getClientRects().length > 0 ? trigger.element : currentControl ?? resultsRef.current;
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  function fitMap() {
    setZoomTouched(true);
    setZoom(fitZoom);
    setPan({ x: 0, y: 0 });
  }

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
  }, [changeZoom, viewMode, hasRelationships]);

  function beginPan(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
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
      setFilterStorageStatus("Saved filters could not be read. Browser storage may be blocked.");
    }
  }, [storageKey]);

  function toggleKind(kind: NodeKind) {
    setSelectedKinds((current) =>
      current.includes(kind) ? current.filter((item) => item !== kind) : [...current, kind],
    );
  }

  function selectNode(nodeId: string, trigger: HTMLElement) {
    const connection = filteredViews.find(({ source, target }) => source.id === nodeId || target.id === nodeId);
    if (connection) {
      setSelectedEdgeId(connection.edge.id);
      inspectionTrigger.current = { element: trigger, edgeId: connection.edge.id };
    } else {
      inspectionTrigger.current = null;
    }
    setFocusNodeId(nodeId);
  }

  function showMap() {
    if (!focusNodeId && snapshot.nodes.length > MAP_NODE_LIMIT) setFocusNodeId(selectedView?.source.id ?? snapshot.nodes[0]?.id ?? null);
    setViewMode("map");
  }

  function showTable() {
    setFocusNodeId(null);
    setViewMode("table");
  }

  function clearFilters() {
    setQuery("");
    setSelectedKinds([]);
    setFocusNodeId(null);
    if (snapshot.nodes.length > MAP_NODE_LIMIT) setViewMode("table");
  }

  function persistFilters(next: SavedFilter[]) {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(next));
      setSavedFilters(next);
      setFilterStorageStatus("Saved filters updated in this browser.");
    } catch {
      setFilterStorageStatus("Could not save this change. Browser storage may be full or blocked; saved filters were not changed.");
    }
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
          <div className="filter-heading-actions">
            <span title={snapshot.mode === "fixture" ? "All records are synthetic sample data" : "Encrypted read-only snapshot of your tenant"}>{snapshot.mode === "fixture" ? "Sample data" : "Live tenant"}</span>
            <button
              className="button button-secondary mobile-filter-toggle"
              type="button"
              disabled={!filtersReady}
              aria-expanded={mobileFiltersOpen}
              aria-controls="relationship-filter-controls"
              onClick={() => setMobileFiltersOpen((open) => !open)}
            >
              {mobileFiltersOpen ? "Hide filters" : "Filters"}
            </button>
          </div>
        </div>

        <div id="relationship-filter-controls" className={`filter-controls ${mobileFiltersOpen ? "is-open" : ""}`}>
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
            {savedFilters.length === 0 ? <small>No saved filters yet.</small> : savedFilters.map((filter) => <div className="saved-filter" key={filter.id}><button type="button" onClick={() => { setQuery(filter.query); setSelectedKinds(filter.nodeKinds); setFocusNodeId(null); if (snapshot.nodes.length > MAP_NODE_LIMIT) setViewMode("table"); }}>{filter.label}</button><button type="button" aria-label={`Remove saved filter ${filter.label}`} onClick={() => persistFilters(savedFilters.filter((item) => item.id !== filter.id))}>×</button></div>)}
            {filterStorageStatus ? <p role="status">{filterStorageStatus}</p> : null}
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
            <p className="legend-note">{snapshot.edges.some(edge => edge.evidence.observed) ? "Observed sign-ins are separate evidence; they do not establish permission use." : "No observed activity is recorded in this snapshot. Missing activity does not establish inactivity."}</p>
          </div>

          {(query || selectedKinds.length > 0) && (
            <button className="button button-secondary button-full" onClick={clearFilters}>
              Clear filters
            </button>
          )}
        </div>
      </aside>

      <section className="map-workspace" aria-label="Relationship results" ref={resultsRef} tabIndex={-1}>
        <div className="map-toolbar">
          <div className="segmented-control" aria-label="Result presentation">
            <button className={viewMode === "map" ? "active" : ""} aria-pressed={viewMode === "map"} onClick={showMap}>Map</button>
            <button className={viewMode === "table" ? "active" : ""} aria-pressed={viewMode === "table"} onClick={showTable}>Table</button>
          </div>
          {viewMode === "map" ? (
            <div className="zoom-control" role="group" aria-label="Map zoom">
              <button type="button" onClick={() => changeZoom(-0.15)} disabled={zoom <= MIN_ZOOM} aria-label="Zoom out">−</button>
              <span aria-live="polite">{Math.round(zoom * 100)}%</span>
              <button type="button" onClick={() => changeZoom(0.15)} disabled={zoom >= MAX_ZOOM} aria-label="Zoom in">+</button>
              <button type="button" className="zoom-fit" onClick={fitMap}>Fit</button>
            </div>
          ) : null}
          <div className="configured-key">
            <span aria-hidden="true" />
            {observedCount ? "Recorded facts and observed sign-ins · inspect evidence" : "Recorded directory facts · no observed activity recorded"}
          </div>
          {viewMode === "map" ? <span className="map-hint" id="map-controls-help">Drag or scroll to pan · Arrow keys pan · Home fits · ⌘/Ctrl + scroll to zoom</span> : null}
        </div>

        {focusNodeId ? <div className="scope-banner"><strong>One-hop view.</strong> Select an object to expand its direct relationships.{neighborhood?.truncated ? ` Limited to ${MAP_NODE_LIMIT} objects; use the table for the complete result.` : ""}</div> : null}
        {unresolvedCount > 0 ? <div className="unresolved-banner" role="status"><strong>{unresolvedCount} unresolved {unresolvedCount === 1 ? "relationship" : "relationships"}.</strong> The source scan was incomplete; inspect evidence before drawing conclusions.</div> : null}

        {filteredViews.length === 0 ? (
          <div className="map-empty">
            <span aria-hidden="true">⌕</span>
            <h2>No relationships match</h2>
            <p>The current snapshot contains data, but the search or object filter hides it.</p>
            <button className="button button-secondary" onClick={clearFilters}>Clear filters</button>
          </div>
        ) : viewMode === "map" ? (
          <div
            className={`relationship-canvas ${panning ? "panning" : ""}`}
            ref={canvasRef}
            role="group"
            tabIndex={0}
            aria-describedby="map-controls-help"
            aria-label={`${visibleNodes.length} objects and ${configuredCount} configured connections${observedCount ? `, ${observedCount} observed sign-in connections` : ""}${incompleteCount ? `, ${incompleteCount} connections with incomplete evidence` : ""}`}
            onPointerDown={beginPan}
            onPointerMove={movePan}
            onPointerUp={endPan}
            onPointerCancel={endPan}
            onLostPointerCapture={() => setPanning(false)}
            onKeyDown={(event) => {
              if (event.target !== event.currentTarget) return;
              if (event.key === "Home") { event.preventDefault(); fitMap(); return; }
              const movement: Record<string, [number, number]> = { ArrowLeft: [50, 0], ArrowRight: [-50, 0], ArrowUp: [0, 50], ArrowDown: [0, -50] };
              const delta = movement[event.key];
              if (!delta) return;
              event.preventDefault();
              const bounds = panBoundsRef.current;
              setPan(current => ({ x: Math.min(bounds.maxX, Math.max(bounds.minX, current.x + delta[0])), y: Math.min(bounds.maxY, Math.max(bounds.minY, current.y + delta[1])) }));
            }}
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
                  onClick={(event) => inspectRelationship(view.edge.id, event.currentTarget)}
                  aria-controls="relationship-evidence"
                  aria-pressed={selectedView?.edge.id === view.edge.id}
                  title={`${view.source.label} ${view.edge.plainLabel} ${view.target.label}: ${label.full}`}
                  aria-label={`${view.source.label} ${view.edge.plainLabel} ${view.target.label}: ${label.full}. ${evidenceLabel(view.edge)} relationship.`}
                >
                  {label.text}
                </button>
              ))}

              {layout.nodes.map(({ node, x, y }) => (
                <button
                  key={node.id}
                  className={`entity-node node-${node.kind} ${selectedView && (selectedView.source.id === node.id || selectedView.target.id === node.id) ? "connected" : ""}`}
                  style={{ left: x, top: y, width: NODE_WIDTH, height: NODE_HEIGHT }}
                  onClick={(event) => selectNode(node.id, event.currentTarget)}
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
          <RelationshipTable key={JSON.stringify([snapshot.id, query, selectedKinds, focusNodeId])} views={filteredViews} selectedEdgeId={selectedView?.edge.id} onSelect={inspectRelationship} />
        )}
      </section>

      <EvidenceInspector view={selectedView} snapshot={snapshot} ref={inspectorRef} onReturn={inspectionRequest ? returnToRelationship : undefined} />
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
  onSelect: (edgeId: string, trigger: HTMLElement) => void;
}) {
  const [page, setPage] = useState(() => Math.floor(Math.max(0, views.findIndex(({ edge }) => edge.id === selectedEdgeId)) / TABLE_PAGE_SIZE));
  const start = page * TABLE_PAGE_SIZE;
  const visible = views.slice(start, start + TABLE_PAGE_SIZE);
  return (
    <div className="relationship-table-wrap">
      <p className="table-result-count" role="status">Showing {start + 1}–{start + visible.length} of {views.length} recorded relationships.</p>
      <table className="relationship-table">
        <caption className="sr-only">Recorded relationships equivalent to the map, with configured and observed evidence distinguished</caption>
        <thead>
          <tr>
            <th>Source</th>
            <th>Relationship</th>
            <th>Target</th>
            <th>Permission</th>
            <th className="table-action-cell">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {visible.map(({ edge, source, target }) => (
            <tr key={edge.id} className={selectedEdgeId === edge.id ? "selected" : ""}>
              <td><strong>{source.label}</strong><small>{kindLabels[source.kind].plain}</small></td>
              <td>{relationshipLabels[edge.type]}<small>{evidenceLabel(edge)}</small></td>
              <td><strong>{target.label}</strong><small>{kindLabels[target.kind].plain}</small></td>
              <td className="mono">{edge.permissions.length > 4 ? `${edge.permissions.slice(0, 4).join(", ")} +${edge.permissions.length - 4} more` : edge.permissions.join(", ") || "—"}</td>
              <td className="table-action-cell"><button className="text-button" type="button" aria-controls="relationship-evidence" aria-pressed={selectedEdgeId === edge.id} onClick={(event) => onSelect(edge.id, event.currentTarget)}>Inspect</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      {views.length > TABLE_PAGE_SIZE ? <nav className="detail-actions" aria-label="Relationship table pages">
        <button type="button" className="button button-secondary" disabled={page === 0} onClick={() => setPage(current => current - 1)}>Previous relationships</button>
        <span>Page {page + 1} of {Math.ceil(views.length / TABLE_PAGE_SIZE)}</span>
        <button type="button" className="button button-secondary" disabled={start + TABLE_PAGE_SIZE >= views.length} onClick={() => setPage(current => current + 1)}>Next relationships</button>
      </nav> : null}
    </div>
  );
}

export function EvidenceInspector({ view, snapshot, ref, onReturn }: { view?: RelationshipView; snapshot: TenantSnapshot; ref?: Ref<HTMLElement>; onReturn?: () => void }) {
  if (!view) {
    return (
      <aside className="evidence-inspector" id="relationship-evidence" ref={ref} tabIndex={-1}>
        <div className="map-empty compact"><h2>No evidence selected</h2></div>
      </aside>
    );
  }

  const { edge, source, target } = view;
  return (
    <aside className="evidence-inspector" id="relationship-evidence" ref={ref} tabIndex={-1} aria-label="Selected relationship evidence" aria-live="polite">
      <div className="inspector-header">
        {onReturn ? <button className="text-button inspector-back" type="button" onClick={onReturn}>Back to selected relationship</button> : null}
        <p className="eyebrow">Why this line exists</p>
        <h2>{edge.plainLabel}</h2>
        <span className="evidence-status"><i aria-hidden="true" /> {edge.evidence.configured ? "Configured relationship" : edge.evidence.observed ? "Observed sign-in" : "Evidence incomplete"}</span>
      </div>

      <div className="plain-explanation">
        <p>{explanation(view)}</p>
        <p className="trust-note">{edge.evidence.configured ? <><strong>Configured access.</strong> This does not prove recent use.</> : edge.evidence.observed ? <><strong>Observed user sign-in.</strong> A successful sign-in does not prove a configured permission was exercised.</> : "Evidence is incomplete; neither configured access nor activity is established."}</p>
      </div>

      {edge.permissions.length > 0 ? (
        <section className="inspector-section">
          <h3>Permission values{edge.permissions.length > 1 ? ` (${edge.permissions.length})` : ""}</h3>
          <PermissionPills permissions={edge.permissions} limit={6} />
        </section>
      ) : null}

      {edge.scope ? (
        <section className="inspector-section evidence-facts">
          <h3>Assignment scope</h3>
          <dl>
            <div><dt>Directory scope</dt><dd>{edge.scope.objectId ? snapshot.nodes.find((node) => node.id === edge.scope?.objectId)?.label ?? "Unresolved administrative unit" : edge.scope.directoryScopeId === "/" ? "Tenant-wide" : "Unresolved scope"}</dd></div>
            <div><dt>Raw scope ID</dt><dd><code>{edge.scope.directoryScopeId}</code></dd></div>
            <div><dt>Scope object ID</dt><dd><code>{edge.scope.objectId ?? "Not resolved"}</code></dd></div>
          </dl>
        </section>
      ) : null}

      <section className="inspector-section entity-pair">
        <h3>Connected objects</h3>
        {[source, target].map((node, index) => (
          <div key={node.id}>
            <small>{index === 0 ? "From" : "To"} · {kindLabels[node.kind].plain}</small>
            <strong>{node.label}</strong>
            <code>{node.id}</code>
            {node.kind === "policy" ? <small>{policySubtype(node.metadata?.policyType)}</small> : null}
            {node.kind === "federatedCredential" ? <small>{String(node.metadata?.issuer ?? "Issuer unavailable")} · {String(node.metadata?.subject ?? "Subject unavailable")}</small> : null}
            {(node.kind === "application" || node.kind === "servicePrincipal") ? (
              <Link href={`/applications/${node.id}`}>Open application detail</Link>
            ) : null}
          </div>
        ))}
      </section>

      <section className="inspector-section evidence-facts">
        <h3>Source evidence</h3>
        <dl>
          {edge.consent ? <><div><dt>Consent audience</dt><dd>{edge.consent.audience === "all-users" ? "All users" : edge.consent.audience === "single-user" ? "One user" : "Unknown consent audience"}</dd></div><div><dt>Consent principal ID</dt><dd><code>{edge.consent.principalId ?? "Not specified"}</code></dd></div></> : null}
          <div><dt>Relationship type</dt><dd><code>{edge.type}</code></dd></div>
          <div><dt>Source endpoint</dt><dd><code>{edge.evidence.sourceEndpoint}</code></dd></div>
          <div><dt>Source record IDs</dt><dd>{edge.evidence.sourceRecordIds.map((id) => <code key={id}>{id}</code>)}</dd></div>
          <div><dt>Collected</dt><dd>{new Date(edge.evidence.scannedAt).toLocaleString("en", { timeZone: "UTC", timeZoneName: "short" })}</dd></div>
          <div><dt>Completeness</dt><dd className="capitalized">{edge.evidence.completeness}</dd></div>
          <div><dt>Observed activity</dt><dd>{edge.evidence.observed ? <>Successful sign-in at <time dateTime={edge.evidence.observed.lastSeenAt}>{edge.evidence.observed.lastSeenAt}</time><br />Requested window starts {edge.evidence.observed.windowStartsAt}</> : "No activity attached to this relationship"}</dd></div>
        </dl>
      </section>

      <div className="inspector-footer">
        <RiskBadge level={source.risk.level} reason={source.risk.reason} />
        <p>{source.risk.reason}</p>
      </div>
    </aside>
  );
}

function policySubtype(value: unknown): string {
  if (value === "conditionalAccess") return "Conditional Access policy";
  if (value === "authorization") return "Authorization policy";
  if (value === "permissionGrant") return "Permission grant policy (consent policy)";
  if (value === "crossTenantAccess") return "Cross-tenant access policy";
  return "Microsoft policy";
}
