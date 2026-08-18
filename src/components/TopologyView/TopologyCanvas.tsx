'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation } from 'd3-force'

import '@xyflow/react/dist/style.css'

export type GraphNode = {
  id: string
  ipAddress?: string
  label: string
  status?: string
  subnet?: string
  type: 'asset' | 'switch'
}

export type GraphEdge = {
  id: string
  label?: string
  source: string
  sourceProtocol?: string
  target: string
  type: 'explicit' | 'subnet'
}

type SimNode = { id: string; x?: number; y?: number }
type SimLink = { source: string; target: string }

const AssetNode = ({ data }: NodeProps) => (
  <div
    className={`topology-node topology-node--asset topology-node--${(data.status as string) ?? 'unknown'}`}
  >
    <Handle position={Position.Top} type="target" />
    <div className="topology-node__label">{data.label as string}</div>
    {data.ipAddress ? <div className="topology-node__ip">{data.ipAddress as string}</div> : null}
    <Handle position={Position.Bottom} type="source" />
  </div>
)

const SwitchNode = ({ data }: NodeProps) => (
  <div className="topology-node topology-node--switch">
    <Handle position={Position.Top} type="target" />
    <div className="topology-node__label">{data.label as string}</div>
    <Handle position={Position.Bottom} type="source" />
  </div>
)

const nodeTypes = { asset: AssetNode, switch: SwitchNode }

const layoutNodes = (
  graphNodes: GraphNode[],
  graphEdges: GraphEdge[],
): Map<string, { x: number; y: number }> => {
  const simNodes: SimNode[] = graphNodes.map((node) => ({ id: node.id }))
  const simLinks: SimLink[] = graphEdges.map((edge) => ({
    source: edge.source,
    target: edge.target,
  }))

  const simulation = forceSimulation(simNodes)
    .force(
      'link',
      forceLink(simLinks)
        .id((d) => (d as SimNode).id)
        .distance(120),
    )
    .force('charge', forceManyBody().strength(-400))
    .force('center', forceCenter(0, 0))
    .force('collide', forceCollide(80))
    .stop()

  for (let i = 0; i < 300; i++) simulation.tick()

  const positions = new Map<string, { x: number; y: number }>()
  for (const node of simNodes) {
    positions.set(node.id, { x: node.x ?? 0, y: node.y ?? 0 })
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

    const edges: Edge[] = graphEdges.map((edge) => ({
      animated: edge.type === 'explicit',
      id: edge.id,
      label: edge.label,
      source: edge.source,
      style:
        edge.type === 'subnet'
          ? { stroke: 'var(--theme-elevation-300)', strokeDasharray: '4 4' }
          : { stroke: 'var(--theme-elevation-600)' },
      target: edge.target,
      type: 'smoothstep',
    }))

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
          if (node.type === 'asset') router.push(`${adminRoute}/collections/assets/${node.id}`)
        }}
      >
        <Background />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(node) =>
            node.type === 'switch' ? 'var(--theme-elevation-300)' : 'var(--theme-elevation-600)'
          }
          pannable
          zoomable
        />
      </ReactFlow>
    </div>
  )
}
