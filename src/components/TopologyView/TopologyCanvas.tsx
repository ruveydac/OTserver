'use client'

import { useRouter } from 'next/navigation'
import { useMemo } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'

import '@xyflow/react/dist/style.css'

export type GraphNode = {
  id: string
  ipAddress?: string
  label: string
  status?: string
  type: 'asset' | 'layer2' | 'router' | 'switch'
}

export type GraphEdge = {
  id: string
  label?: string
  source: string
  sourceProtocol?: string
  target: string
  type: 'explicit' | 'layer2'
}

const NodeHandles = () => (
  <>
    <Handle id="top" position={Position.Top} type="target" />
    <Handle id="right" position={Position.Right} type="source" />
    <Handle id="bottom" position={Position.Bottom} type="source" />
    <Handle id="left" position={Position.Left} type="target" />
  </>
)

const RouterIcon = () => (
  <svg aria-hidden="true" viewBox="0 0 64 64">
    <ellipse cx="32" cy="22" rx="27" ry="14" />
    <path d="M5 22v20c0 8 12 14 27 14s27-6 27-14V22M20 16l9 5m-9-5 1 6m-1-6 7 1m17-1-9 5m9-5-1 6m1-6-7 1M20 28l9-5m-9 5 1-6m-1 6 7-1m17 1-9-5m9 5-1-6m1 6-7-1" />
  </svg>
)

const Layer3SwitchIcon = () => (
  <svg aria-hidden="true" viewBox="0 0 64 64">
    <path d="M5 15 15 6h43v43L48 58H5Zm0 0h43L58 6M48 15v43" />
    <circle cx="27" cy="36" r="7" />
    <path d="M27 29v-9m0 0-3 3m3-3 3 3m-3 20v9m0 0-3-3m3 3 3-3M20 36h-9m0 0 3-3m-3 3 3 3m20-3h9m0 0-3-3m3 3-3 3M22 31l-6-6m0 0 4 1m-4-1 1 4m15 2 6-6m0 0-1 4m1-4-4 1M32 41l6 6m0 0-4-1m4 1-1-4M22 41l-6 6m0 0 1-4m-1 4 4-1" />
  </svg>
)

const Layer2Icon = () => (
  <svg aria-hidden="true" viewBox="0 0 64 64">
    <path d="M5 17 15 8h43v37L48 54H5Zm0 0h43L58 8M48 17v37M13 29h28m0 0-6-5m6 5-6 5m8 9H15m0 0 6-5m-6 5 6 5" />
  </svg>
)

const AssetNode = ({ data }: NodeProps) => (
  <div
    className={`topology-node topology-node--asset topology-node--${(data.status as string) ?? 'unknown'}`}
  >
    <NodeHandles />
    <div className="topology-node__label">{data.label as string}</div>
    {data.ipAddress ? <div className="topology-node__ip">{data.ipAddress as string}</div> : null}
  </div>
)

const SwitchNode = ({ data }: NodeProps) => (
  <div className="topology-node topology-node--network topology-node--switch">
    <NodeHandles />
    <div className="topology-node__symbol">
      <Layer3SwitchIcon />
    </div>
    <div className="topology-node__label">{data.label as string}</div>
  </div>
)

const RouterNode = ({ data }: NodeProps) => (
  <div className="topology-node topology-node--network topology-node--router">
    <NodeHandles />
    <div className="topology-node__symbol">
      <RouterIcon />
    </div>
    <div className="topology-node__label">{data.label as string}</div>
  </div>
)

const Layer2Node = ({ data }: NodeProps) => (
  <div className="topology-node topology-node--layer2 topology-node--network">
    <NodeHandles />
    <div className="topology-node__symbol">
      <Layer2Icon />
    </div>
    <div className="topology-node__label">{data.label as string}</div>
  </div>
)

const nodeTypes = { asset: AssetNode, layer2: Layer2Node, router: RouterNode, switch: SwitchNode }

const nodeRank: Record<GraphNode['type'], number> = { router: 0, switch: 1, layer2: 2, asset: 3 }

const layoutNodes = (
  graphNodes: GraphNode[],
  graphEdges: GraphEdge[],
): Map<string, { x: number; y: number }> => {
  const byId = new Map(graphNodes.map((node) => [node.id, node]))
  const neighbors = new Map(graphNodes.map((node) => [node.id, new Set<string>()]))
  for (const edge of graphEdges) {
    if (!byId.has(edge.source) || !byId.has(edge.target)) continue
    neighbors.get(edge.source)?.add(edge.target)
    neighbors.get(edge.target)?.add(edge.source)
  }
  const positions = new Map<string, { x: number; y: number }>()
  const remaining = new Set(byId.keys())
  let componentX = 0

  while (remaining.size) {
    const first = remaining.values().next().value as string
    const component: string[] = []
    const pending = [first]
    remaining.delete(first)
    while (pending.length) {
      const id = pending.shift()!
      component.push(id)
      for (const neighbor of neighbors.get(id) ?? []) {
        if (!remaining.delete(neighbor)) continue
        pending.push(neighbor)
      }
    }

    const root = component.sort((left, right) => {
      const rank = nodeRank[byId.get(left)!.type] - nodeRank[byId.get(right)!.type]
      if (rank) return rank
      return (neighbors.get(right)?.size ?? 0) - (neighbors.get(left)?.size ?? 0)
    })[0]
    const depths = new Map([[root, 0]])
    const queue = [root]
    while (queue.length) {
      const id = queue.shift()!
      for (const neighbor of neighbors.get(id) ?? []) {
        if (depths.has(neighbor)) continue
        depths.set(neighbor, depths.get(id)! + 1)
        queue.push(neighbor)
      }
    }

    const rows = new Map<number, string[]>()
    for (const id of component) {
      const depth = depths.get(id) ?? 0
      const row = rows.get(depth) ?? []
      row.push(id)
      rows.set(depth, row)
    }
    const widestRow = Math.max(...[...rows.values()].map((row) => row.length))
    const componentWidth = Math.max(220, widestRow * 260)
    for (const [depth, row] of rows) {
      row.sort((left, right) => byId.get(left)!.label.localeCompare(byId.get(right)!.label))
      const rowWidth = row.length * 260
      row.forEach((id, index) => {
        positions.set(id, {
          x: componentX + (componentWidth - rowWidth) / 2 + index * 260,
          y: depth * 170,
        })
      })
    }
    componentX += componentWidth + 180
  }
  return positions
}

export const TopologyCanvas = ({
  adminRoute,
  edges: graphEdges,
  nodes: graphNodes,
}: {
  adminRoute: string
  edges: GraphEdge[]
  nodes: GraphNode[]
}) => {
  const router = useRouter()

  const { edges, nodes } = useMemo(() => {
    const positions = layoutNodes(graphNodes, graphEdges)

    const nodes: Node[] = graphNodes.map((node) => ({
      data: { ipAddress: node.ipAddress, label: node.label, status: node.status },
      id: node.id,
      position: positions.get(node.id) ?? { x: 0, y: 0 },
      type: node.type,
    }))

    const edges: Edge[] = graphEdges.map((edge) => {
      let source = edge.source
      let target = edge.target
      let sourceHandle = 'bottom'
      let targetHandle = 'top'
      const sourcePosition = positions.get(source) ?? { x: 0, y: 0 }
      const targetPosition = positions.get(target) ?? { x: 0, y: 0 }
      const horizontal = sourcePosition.y === targetPosition.y
      if (horizontal ? sourcePosition.x > targetPosition.x : sourcePosition.y > targetPosition.y) {
        const previousSource = source
        source = target
        target = previousSource
      }
      if (horizontal) {
        sourceHandle = 'right'
        targetHandle = 'left'
      }
      return {
        id: edge.id,
        label: edge.label,
        markerEnd: { type: MarkerType.ArrowClosed },
        markerStart: { type: MarkerType.ArrowClosed },
        source,
        sourceHandle,
        style:
          edge.type === 'layer2'
            ? { stroke: 'var(--theme-elevation-400)', strokeDasharray: '5 5' }
            : { stroke: 'var(--theme-elevation-700)', strokeWidth: 1.5 },
        target,
        targetHandle,
        type: 'smoothstep',
      }
    })

    return { edges, nodes }
  }, [graphEdges, graphNodes])

  return (
    <div className="topology-view__canvas">
      <ReactFlow
        edges={edges}
        fitView
        maxZoom={2}
        minZoom={0.1}
        nodeTypes={nodeTypes}
        nodes={nodes}
        nodesConnectable={false}
        nodesDraggable
        onNodeDoubleClick={(_event, node) => {
          if (node.type !== 'layer2') router.push(`${adminRoute}/collections/assets/${node.id}`)
        }}
      >
        <Background gap={24} variant={BackgroundVariant.Lines} />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(node) =>
            node.type === 'asset' ? 'var(--theme-elevation-600)' : 'var(--theme-success-500)'
          }
          pannable
          zoomable
        />
      </ReactFlow>
    </div>
  )
}
