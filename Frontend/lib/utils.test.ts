import { describe, it, expect } from 'vitest'
import { cn } from './utils'

describe('cn utility', () => {
  it('should merge basic strings', () => {
    expect(cn('class1', 'class2')).toBe('class1 class2')
  })

  it('should handle conditional classes with objects', () => {
    expect(cn('base', { 'active': true, 'inactive': false })).toBe('base active')
  })

  it('should handle arrays of classes', () => {
    expect(cn(['class1', 'class2'], 'class3')).toBe('class1 class2 class3')
  })

  it('should ignore falsy values', () => {
    expect(cn('class1', null, undefined, false, '', 'class2')).toBe('class1 class2')
  })

  it('should correctly merge Tailwind classes, overriding previous ones', () => {
    // twMerge behavior: p-4 overrides p-2
    expect(cn('p-2 text-red-500', 'p-4')).toBe('text-red-500 p-4')

    // twMerge behavior: bg-blue-500 overrides bg-red-500
    expect(cn('bg-red-500', 'bg-blue-500')).toBe('bg-blue-500')
  })

  it('should handle complex combinations', () => {
    const isActive = true
    const isHovered = false

    expect(cn(
      'base-class p-4',
      isActive && 'bg-blue-500',
      isHovered && 'hover:bg-blue-600',
      { 'opacity-50': !isActive, 'text-white': isActive },
      ['additional-1', 'additional-2'],
      // Override p-4 from earlier
      'p-6'
    )).toBe('base-class bg-blue-500 text-white additional-1 additional-2 p-6')
  })
})
