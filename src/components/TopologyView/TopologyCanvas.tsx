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
    <circle cx="32" cy="32" r="29" />
    <path d="m21 21 9 9m-9-9v7m0-7h7m15 0-9 9m9-9v7m0-7h-7M21 43l9-9m-9 9v-7m0 7h7m15 0-9-9m9 9v-7m0 7h-7" />
  </svg>
)

const CoreSwitchIcon = () => (
  <svg aria-hidden="true" viewBox="0 0 64 64">
    <rect height="56" rx="5" width="56" x="4" y="4" />
    <path d="M32 13v12m0-12-5 5m5-5 5 5m0 28V34m0 12-5-5m5 5 5-5M13 32h12m-12 0 5-5m-5 5 5 5m28-5H34m12 0-5-5m5 5-5 5" />
    <circle cx="32" cy="32" r="6" />
  </svg>
)

const Layer2Icon = () => (
  <svg aria-hidden="true" viewBox="0 0 64 64">
    <rect height="48" rx="5" width="56" x="4" y="8" />
    <path d="M15 24h32m0 0-7-6m7 6-7 6m9 10H17m0 0 7-6m-7 6 7 6" />
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
      <CoreSwitchIcon />
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
      const horizontal =
        Math.abs(sourcePosition.x - targetPosition.x) >
        Math.abs(sourcePosition.y - targetPosition.y)
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
