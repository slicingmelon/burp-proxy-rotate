/**
 * Burp Proxy Rotate
 * Author: slicingmelon 
 * https://github.com/slicingmelon
 * https://x.com/pedro_infosec
 * 
 * This burp extension routes each HTTP request through a different proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * High-performance buffer pool to avoid frequent direct buffer allocations
 */
public class BufferPool {
    private final ConcurrentLinkedQueue<ByteBuffer> smallBuffers = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<ByteBuffer> mediumBuffers = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<ByteBuffer> largeBuffers = new ConcurrentLinkedQueue<>();
    
    private final int SMALL_SIZE = 8192;   // 8KB
    private final int MEDIUM_SIZE = 65536; // 64KB  
    private final int LARGE_SIZE = 262144; // 256KB
    
    private final AtomicInteger smallCount = new AtomicInteger(0);
    private final AtomicInteger mediumCount = new AtomicInteger(0);
    private final AtomicInteger largeCount = new AtomicInteger(0);
    
    private final int MAX_POOLED_BUFFERS = 200; // Increased for high-volume scanning
    
    /**
     * Get a buffer of appropriate size
     */
    public ByteBuffer acquire(int minSize) {
        if (minSize <= SMALL_SIZE) {
            ByteBuffer buffer = smallBuffers.poll();
            if (buffer != null) {
                smallCount.decrementAndGet(); // Fix: decrement count when taking from pool
                buffer.clear();
                return buffer;
            }
            return ByteBuffer.allocateDirect(SMALL_SIZE);
        } else if (minSize <= MEDIUM_SIZE) {
            ByteBuffer buffer = mediumBuffers.poll();
            if (buffer != null) {
                mediumCount.decrementAndGet(); // Fix: decrement count when taking from pool
                buffer.clear();
                return buffer;
            }
            return ByteBuffer.allocateDirect(MEDIUM_SIZE);
        } else {
            ByteBuffer buffer = largeBuffers.poll();
            if (buffer != null) {
                largeCount.decrementAndGet(); // Fix: decrement count when taking from pool
                buffer.clear();
                return buffer;
            }
            return ByteBuffer.allocateDirect(LARGE_SIZE);
        }
    }
    
    /**
     * Return a buffer to the pool
     */
    public void release(ByteBuffer buffer) {
        if (buffer == null || !buffer.isDirect()) {
            return;
        }
        
        buffer.clear();
        int capacity = buffer.capacity();
        
        // Accept buffers that are close to our standard sizes (within 10% difference)
        if (isCloseToSize(capacity, SMALL_SIZE) && smallCount.get() < MAX_POOLED_BUFFERS) {
            smallBuffers.offer(buffer);
            smallCount.incrementAndGet();
        } else if (isCloseToSize(capacity, MEDIUM_SIZE) && mediumCount.get() < MAX_POOLED_BUFFERS) {
            mediumBuffers.offer(buffer);
            mediumCount.incrementAndGet();
        } else if (isCloseToSize(capacity, LARGE_SIZE) && largeCount.get() < MAX_POOLED_BUFFERS) {
            largeBuffers.offer(buffer);
            largeCount.incrementAndGet();
        }
        // If pool is full or size doesn't match, let GC handle the buffer
    }
    
    /**
     * Check if buffer size is close enough to a standard size to be pooled
     */
    private boolean isCloseToSize(int actualSize, int standardSize) {
        return Math.abs(actualSize - standardSize) <= (standardSize * 0.1);
    }
    
    /**
     * Pre-allocate buffers for better performance
     * Optimized for high-volume scanning workloads
     */
    public void warmUp() {
        // Pre-allocate more small buffers for SOCKS handshakes and small requests
        for (int i = 0; i < 50; i++) {
            smallBuffers.offer(ByteBuffer.allocateDirect(SMALL_SIZE));
            smallCount.incrementAndGet();
        }
        for (int i = 0; i < 15; i++) {
            mediumBuffers.offer(ByteBuffer.allocateDirect(MEDIUM_SIZE));
            mediumCount.incrementAndGet();
        }
        for (int i = 0; i < 5; i++) {
            largeBuffers.offer(ByteBuffer.allocateDirect(LARGE_SIZE));
            largeCount.incrementAndGet();
        }
    }
    
    /**
     * Get pool statistics
     */
    public String getStats() {
        return String.format("BufferPool: Small=%d, Medium=%d, Large=%d", 
                           smallBuffers.size(), mediumBuffers.size(), largeBuffers.size());
    }
} 