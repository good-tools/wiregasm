<template>
  <span>
    <span @click="e => handleClickWithOffset(e, 0)">{{ before }}</span>
    <span class="bg-gray-600 text-white" @click="e => handleClickWithOffset(e, before.length)">
      <span>{{ hl }}</span>
    </span>
    <span @click="e => handleClickWithOffset(e, before.length + hl.length)">{{ end }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  text: string
  start: number
  size: number
}>()

const emit = defineEmits<{
  (e: 'offsetClicked', offset: number): void
}>()

const before = computed(() => props.text.substring(0, props.start))
const hl = computed(() => props.text.substring(props.start, props.start + props.size))
const end = computed(() => props.text.substring(props.start + props.size))

const handleClickWithOffset = (_: MouseEvent, offset: number) => {
  const selection = window.getSelection()
  if (selection) {
    emit('offsetClicked', selection.anchorOffset + offset)
  }
}
</script>
