<template>
  <div :class="[props.root ? 'overflow-x-auto w-auto' : 'pl-2 border-l']">
    <div v-for="(node, i) in props.tree" :key="`${props.id}-${i}`" class="leading-relaxed">
      <div
        :class="[
          'flex items-center min-w-fit w-full',
          node.length > 0 ? 'cursor-pointer' : 'cursor-default',
          `${props.id}-${i}` === props.selected ? 'bg-gray-600 text-white' : 'text-gray-500'
        ]"
      >
        <template v-if="node.tree && node.tree.length > 0">
          <a class="cursor-pointer flex flex-grow-0" @click.stop="toggle(`${props.id}-${i}`)">
            <v-icon
              icon="arrows-r"
              :color="`${props.id}-${i}` === props.selected ? 'white' : '#666'"
              class="shrink-0 !w-2.5 !h-2.5 transition-transform duration-200"
              :class="{
                'rotate-90': isOpen(`${props.id}-${i}`),
                'text-white': `${props.id}-${i}` === props.selected
              }"
            />
          </a>
        </template>
        <v-icon v-else icon="v-remove" class="shrink-0 !w-2.5 !h-2.5 text-gray-500" />

        <div
          class="ml-1 flex-1 whitespace-nowrap overflow-visible font-mono text-xs select-none"
          @click="e => handleClick(e, node, `${props.id}-${i}`)"
          @dblclick="() => toggle(`${props.id}-${i}`)"
        >
          {{ node.label }}
        </div>
      </div>

      <DissectionTree
        v-show="node.tree && node.tree.length > 0 && isOpen(`${props.id}-${i}`)"
        :id="`${props.id}-${i}`"
        :tree="node.tree || []"
        :select="props.select"
        :selected="props.selected"
        :set-filter="props.setFilter"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

const NO_SELECTION = { id: '', idx: 0, start: 0, length: 0 } // 假设这个常量从别处导入

export interface TreeNode {
  label: string
  tree: TreeNode[]
  length: number
  data_source_idx?: number
  start?: number
  filter?: string
}

interface Props {
  id: string
  tree: TreeNode[]
  select?: (selection: any) => void
  root?: boolean
  selected?: string
  setFilter?: (filter: string) => void
}

const props = withDefaults(defineProps<Props>(), {
  select: () => ({}),
  root: false,
  selected: '',
  setFilter: undefined
})

// DissectionSubTree 的逻辑
const openStates = ref(new Map<string, boolean>())

const isOpen = (nodeId: string) => openStates.value.get(nodeId) || false

watch(
  () => [props.selected, props.id],
  () => {
    props.tree.forEach((_, i) => {
      const nodeId = `${props.id}-${i}`
      if (!isOpen(nodeId) && props.selected.startsWith(nodeId + '-')) {
        openStates.value.set(nodeId, true)
      }
    })
  }
)

const toggle = (nodeId: string) => {
  const currentState = isOpen(nodeId)

  const newOpenStates = new Map(openStates.value)
  newOpenStates.set(nodeId, !currentState)
  openStates.value = newOpenStates

  if (currentState && props.selected.startsWith(nodeId + '-')) {
    props.select(NO_SELECTION)
  }
}

const handleClick = (e: MouseEvent, node: TreeNode, nodeId: string) => {
  if (e.detail === 2 && props.setFilter && node.filter) {
    props.setFilter(node.filter)
  }

  if (node.length > 0) {
    props.select({
      id: nodeId,
      idx: node.data_source_idx,
      start: node.start,
      length: node.length
    })
  }
}
</script>
