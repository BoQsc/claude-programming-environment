#[compute]
#version 450

// Work group of 8x8x8 threads (512 total)
layout(local_size_x = 8, local_size_y = 8, local_size_z = 8) in;

// Voxel data output buffer
layout(set = 0, binding = 0, std430) restrict buffer VoxelData {
    float density[];
} voxel_data;

// Parameters for generation
layout(set = 0, binding = 1, std430) restrict buffer readonly Parameters {
    vec3 chunk_position;
    float noise_scale;
    float height_scale;
    uint chunk_size;
} params;

// Simple 3D noise function (improved for better terrain)
float noise3d(vec3 p) {
    // Multi-octave noise for better terrain features
    float result = 0.0;
    result += sin(p.x * 0.1) * sin(p.y * 0.1) * sin(p.z * 0.1) * 1.0;
    result += sin(p.x * 0.2) * sin(p.y * 0.2) * sin(p.z * 0.2) * 0.5;
    result += sin(p.x * 0.4) * sin(p.y * 0.4) * sin(p.z * 0.4) * 0.25;
    result += sin(p.x * 0.8) * sin(p.y * 0.8) * sin(p.z * 0.8) * 0.125;
    return result;
}

void main() {
    // Get 3D position of current voxel
    ivec3 voxel_pos = ivec3(gl_GlobalInvocationID.xyz);
    
    // Check bounds
    if (voxel_pos.x >= int(params.chunk_size) || 
        voxel_pos.y >= int(params.chunk_size) || 
        voxel_pos.z >= int(params.chunk_size)) {
        return;
    }
    
    // Calculate world position
    vec3 world_pos = params.chunk_position + vec3(voxel_pos);
    
    // Generate height-based terrain with better distribution
    float height = noise3d(world_pos * params.noise_scale) * params.height_scale;
    
    // Create density: positive = solid, negative = empty
    // Adjust for chunk center (make terrain appear in middle of chunk)
    float terrain_height = height + float(params.chunk_size) * 0.5;
    float density = terrain_height - world_pos.y;
    
    // Store in buffer
    uint index = uint(voxel_pos.x + voxel_pos.y * int(params.chunk_size) + voxel_pos.z * int(params.chunk_size) * int(params.chunk_size));
    voxel_data.density[index] = density;
}