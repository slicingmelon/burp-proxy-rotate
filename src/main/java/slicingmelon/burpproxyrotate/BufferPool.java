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
    
    private final int MAX_POOLED_BUFFERS = 100;
    
    /**
     * Get a buffer of appropriate size
     */
    public ByteBuffer acquire(int minSize) {
        if (minSize <= SMALL_SIZE) {
            ByteBuffer buffer = smallBuffers.poll();
            if (buffer != null) {
                buffer.clear();
                return buffer;
            }
            return ByteBuffer.allocateDirect(SMALL_SIZE);
        } else if (minSize <= MEDIUM_SIZE) {
            ByteBuffer buffer = mediumBuffers.poll();
            if (buffer != null) {
                buffer.clear();
                return buffer;
            }
            return ByteBuffer.allocateDirect(MEDIUM_SIZE);
        } else {
            ByteBuffer buffer = largeBuffers.poll();
            if (buffer != null) {
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
        
        if (capacity == SMALL_SIZE && smallCount.get() < MAX_POOLED_BUFFERS) {
            smallBuffers.offer(buffer);
            smallCount.incrementAndGet();
        } else if (capacity == MEDIUM_SIZE && mediumCount.get() < MAX_POOLED_BUFFERS) {
            mediumBuffers.offer(buffer);
            mediumCount.incrementAndGet();
        } else if (capacity == LARGE_SIZE && largeCount.get() < MAX_POOLED_BUFFERS) {
            largeBuffers.offer(buffer);
            largeCount.incrementAndGet();
        }
        // If pool is full, let GC handle the buffer
    }
    
    /**
     * Pre-allocate buffers for better performance
     */
    public void warmUp() {
        // Pre-allocate some buffers
        for (int i = 0; i < 20; i++) {
            smallBuffers.offer(ByteBuffer.allocateDirect(SMALL_SIZE));
            smallCount.incrementAndGet();
        }
        for (int i = 0; i < 10; i++) {
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