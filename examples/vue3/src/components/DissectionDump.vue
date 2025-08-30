<template>
  <div class="flex font-mono text-xs whitespace-pre break-all">
    <div class="tbd-offset select-none text-gray-500">{{ addrLines.join('\n') }}</div>
    <div class="ml-4 cursor-pointer">
      <HighlightedText
        :text="hexLines.join('\n')"
        :start="hexHighlight[0]"
        :size="hexHighlight[1]"
        @offsetClicked="onHexClick"
      />
    </div>
    <div class="ml-4 cursor-pointer">
      <HighlightedText
        :text="asciiLines.join('\n')"
        :start="asciiHighlight[0]"
        :size="asciiHighlight[1]"
        @offsetClicked="onAsciiClick"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import HighlightedText from './HighlightedText.vue'

// Props 定义
const props = defineProps<{
  buffer: Uint8Array
  selected: [number, number]
}>()

const emit = defineEmits<{
  (e: 'select', offset: number): void
}>()

// 响应式状态
const addrLines = ref<string[]>([])
const hexLines = ref<string[]>([])
const asciiLines = ref<string[]>([])
const asciiHighlight = ref<[number, number]>([0, 0])
const hexHighlight = ref<[number, number]>([0, 0])

// 监听选中变化
watch(
  () => props.selected,
  ([start, size]) => {
    const hexSize = size * 2 + size - 1
    const hexPos = start * 2 + start
    const asciiPos = start + Math.floor(start / 16)
    const asciiSize = start + size + Math.floor((start + size) / 16) - asciiPos

    asciiHighlight.value = [asciiPos, size > 0 ? asciiSize : 0]
    hexHighlight.value = [hexPos, size > 0 ? hexSize : 0]
  }
)

// 监听buffer变化
watch(
  () => props.buffer,
  buffer => {
    const addr_lines: string[] = []
    const hex_lines: string[] = []
    const ascii_lines: string[] = []

    for (let i = 0; i < buffer.length; i += 16) {
      const address = i.toString(16).padStart(8, '0')
      const block = buffer.slice(i, i + 16)
      const hexArray: string[] = []
      const asciiArray: string[] = []

      for (const value of block) {
        hexArray.push(value.toString(16).padStart(2, '0'))
        asciiArray.push(value >= 0x20 && value < 0x7f ? String.fromCharCode(value) : '.')
      }

      const hexString =
        hexArray.length > 8
          ? hexArray.slice(0, 8).join(' ') + '　' + hexArray.slice(8).join(' ')
          : hexArray.join(' ')

      addr_lines.push(address)
      hex_lines.push(hexString)
      ascii_lines.push(asciiArray.join(''))
    }

    addrLines.value = addr_lines
    hexLines.value = hex_lines
    asciiLines.value = ascii_lines
  },
  { immediate: true }
)

// 事件处理函数
const onHexClick = (offset: number) => {
  emit('select', Math.floor(offset / 3))
}

const onAsciiClick = (offset: number) => {
  emit('select', offset - Math.floor(offset / 17))
}
</script>

<script lang="ts">
// HighlightedText 组件定义
export default {
  name: 'DissectionDump'
}
</script>
