package org.fmalyshev.quic.struct;

import org.jspecify.annotations.NonNull;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class SortedIntervals implements AutoCloseable, Iterable<SortedIntervals.Interval> {
    public record Interval(int lower, int higher) {}

    private final Arena arena;
    private final MemorySegment segment;
    private final MemorySegment reclaimed;
    private final int capacity;
    private int nextReclaimed = 0;
    private int lastReclaimed = 0;
    private int numReclaimed = 0;
    private int nodeCount = 0;
    private int rootIndex = -1;

    private static final long NODE_SIZE = 20; // 5 ints * 4 bytes
    private static final int NULL = -1;

    public SortedIntervals(int capacity) {
        if (capacity > 255) { throw new IllegalArgumentException("capacity > 255"); }
        this.arena = Arena.ofConfined();
        this.capacity = capacity;
        // Allocate fixed block of native memory upfront
        this.segment = arena.allocate(capacity * NODE_SIZE, 16);
        this.reclaimed = arena.allocate(capacity, 16);
    }

    private byte nextReclaimed() {
        numReclaimed--;
        return reclaimed.get(ValueLayout.JAVA_BYTE, (nextReclaimed++) % capacity);
    }

    private void addReclaimed(byte val) {
        numReclaimed++;
        reclaimed.set(ValueLayout.JAVA_BYTE, (lastReclaimed++) % capacity, val);
    }

    // --- Fast Native Off-Heap Getters & Setters ---
    private int getStart(int idx) { return segment.get(ValueLayout.JAVA_INT, idx * NODE_SIZE); }
    private void setStart(int idx, int val) { segment.set(ValueLayout.JAVA_INT, idx * NODE_SIZE, val); }

    private int getEnd(int idx) { return segment.get(ValueLayout.JAVA_INT, idx * NODE_SIZE + 4); }
    private void setEnd(int idx, int val) { segment.set(ValueLayout.JAVA_INT, idx * NODE_SIZE + 4, val); }

    private int getLeft(int idx) { return segment.get(ValueLayout.JAVA_INT, idx * NODE_SIZE + 8); }
    private void setLeft(int idx, int val) {
        segment.set(ValueLayout.JAVA_INT, idx * NODE_SIZE + 8, val);
    }

    private int getRight(int idx) { return segment.get(ValueLayout.JAVA_INT, idx * NODE_SIZE + 12); }
    private void setRight(int idx, int val) {
        segment.set(ValueLayout.JAVA_INT, idx * NODE_SIZE + 12, val);
    }

    private int getParent(int idx) { return segment.get(ValueLayout.JAVA_INT, idx * NODE_SIZE + 16); }
    private void setParent(int idx, int val) { segment.set(ValueLayout.JAVA_INT, idx * NODE_SIZE + 16, val); }

    /**
     * Inserts a single unit point 'x' into the off-heap sorted tree,
     * merging neighbors automatically in-place if they touch.
     */
    public void add(int x) {
        if (rootIndex == -1) {
            rootIndex = createNode(x, x);
            return;
        }

        int curr = rootIndex;
        int parent = NULL;

        // 1. Locate position via O(log n) tree traversal
        while (curr != NULL) {
            parent = curr;
            int start = getStart(curr);
            int end = getEnd(curr);

            if (x >= start && x <= end) return; // Point already enclosed! Exit early.

            if (x < start) {
                curr = getLeft(curr);
            } else {
                curr = getRight(curr);
            }
        }

        // 2. We fell off the tree. Check structural neighbors for potential O(1) in-place merges
        int leftNeighbor = (x < getStart(parent)) ? getPredecessor(parent) : parent;
        int rightNeighbor = (x < getStart(parent)) ? parent : getSuccessor(parent);

        int finalStart = x;
        int finalEnd = x;
        int mergedTargetIdx = NULL;

        if (leftNeighbor != NULL && getEnd(leftNeighbor) == x - 1) {
            finalStart = getStart(leftNeighbor);
            mergedTargetIdx = leftNeighbor;
        }

        if (rightNeighbor != NULL && getStart(rightNeighbor) == x + 1) {
            finalEnd = getEnd(rightNeighbor);
            if (mergedTargetIdx != NULL) {
                // Bridge gap: Left and right merge together!
                setEnd(leftNeighbor, finalEnd);
                removeNode(rightNeighbor); // Delete the redundant node
                return;
            } else {
                mergedTargetIdx = rightNeighbor;
            }
        }

        if (mergedTargetIdx != NULL) {
            // Overwrite boundaries directly in native memory (Zero structural changes to tree)
            setStart(mergedTargetIdx, finalStart);
            setEnd(mergedTargetIdx, finalEnd);
        } else {
            // Pure isolated insertion required
            int newNode = createNode(x, x);
            setParent(newNode, parent);
            if (x < getStart(parent)) setLeft(parent, newNode);
            else setRight(parent, newNode);
        }
    }

    private int createNode(int start, int end) {
        int idx;
        nodeCount++;
        if (numReclaimed == 0) {
            if (nodeCount > capacity) {
                throw new IllegalStateException("Capacity exceeded");
            }
            idx = nodeCount-1;
        } else {
            idx = nextReclaimed();
        }
        setStart(idx, start);
        setEnd(idx, end);
        setLeft(idx, NULL);
        setRight(idx, NULL);
        setParent(idx, NULL);
        return idx;
    }

    // --- O(1) Amortized Structural Navigation Pointers ---
    private int getSuccessor(int idx) {
        if (idx == NULL) return NULL;
        int r = getRight(idx);
        if (r != NULL) {
            while (getLeft(r) != NULL) r = getLeft(r);
            return r;
        }
        int p = getParent(idx);
        while (p != NULL && idx == getRight(p)) {
            idx = p;
            p = getParent(p);
        }
        return p;
    }

    private int getPredecessor(int idx) {
        if (idx == NULL) return NULL;
        int l = getLeft(idx);
        if (l != NULL) {
            while (getRight(l) != NULL) l = getRight(l);
            return l;
        }
        int p = getParent(idx);
        while (p != NULL && idx == getLeft(p)) {
            idx = p;
            p = getParent(p);
        }
        return p;
    }

    private void removeNode(int target) {
        if (target == NULL) return;

        // Case 1: Node has two children
        if (getLeft(target) != NULL && getRight(target) != NULL) {
            // Find the in-order successor (the smallest node in the right subtree)
            int successor = getRight(target);
            while (getLeft(successor) != NULL) {
                successor = getLeft(successor);
            }

            // Swap values: copy the successor's data directly over the target data
            setStart(target, getStart(successor));
            setEnd(target, getEnd(successor));

            // Now, delete the original successor node instead (which is guaranteed to have at most one child)
            target = successor;
        }

        // Identify the replacement node: the single child, or NULL if it's a leaf node
        int child = (getLeft(target) != NULL) ? getLeft(target) : getRight(target);
        int parent = getParent(target);

        // Case 2 & 3: Node has one child or is a leaf node
        if (child != NULL) {
            setParent(child, parent); // Link the child directly up to the parent
        }

        if (parent == NULL) {
            // Target was the root of the entire tree
            rootIndex = child;
        } else if (target == getLeft(parent)) {
            // Target was a left child
            setLeft(parent, child);
        } else {
            // Target was a right child
            setRight(parent, child);
        }

        // Safety Cleanup: Sever all native pointer links on the deleted node slot
        setLeft(target, NULL);
        setRight(target, NULL);
        setParent(target, NULL);

        addReclaimed((byte) target);
        nodeCount--;
    }

    /**
     * Streams the intervals sequentially in sorted order in O(n) time
     * without performing any sorting operations.
     */

    @Override
    @NonNull
    public Iterator<Interval> iterator() {
        return new Iterator<>() {
            private int current;
            private final int[] stack = new int[capacity];
            private int sti = 0;
            {
                current = rootIndex;
                if (current != NULL) {
                    while (getRight(current) != NULL) {
                        stack[sti++] = current;
                        current = getRight(current);
                    }
                }
            }

            @Override
            public boolean hasNext() {
                return current != NULL;
            }

            @Override
            public Interval next() {
                if (!hasNext()) throw new NoSuchElementException();
                int res = current;
                if (getLeft(current) != NULL) {
                    current = getLeft(current);
                    while (getRight(current) != NULL) {
                        stack[sti++] = current;
                        current = getRight(current);
                    }
                } else if (sti > 0) {
                    current = stack[--sti];
                } else {
                    current = NULL;
                }

                return new Interval(getStart(res), getEnd(res));
            }
        };
    }

    public boolean isEmpty() {
        return rootIndex == NULL;
    }

    public int size() {
        return nodeCount;
    }

    @Override
    public void close() { arena.close(); } // Instantly wipes memory back to the OS
}