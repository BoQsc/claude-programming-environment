#[compute]
#version 450

// Work group for mesh generation
layout(local_size_x = 8, local_size_y = 8, local_size_z = 8) in;

// Input voxel data
layout(set = 0, binding = 0, std430) restrict buffer readonly VoxelData {
    float density[];
} voxel_data;

// Output vertex data (position, normal, uv)
layout(set = 0, binding = 1, std430) restrict buffer VertexData {
    float data[]; // Stores position (vec3), normal (vec3), uv (vec2) for each vertex
} vertex_data;

// Output index data
layout(set = 0, binding = 2, std430) restrict buffer IndexData {
    uint indices[];
} index_data;

// Atomic counter for vertex/index count
layout(set = 0, binding = 3, std430) restrict buffer AtomicCounter {
    uint vertex_count; // Number of *vertices* (not floats)
    uint index_count;
} counter;

// Parameters
layout(set = 0, binding = 4, std430) restrict buffer readonly MeshParams {
    uint chunk_size;
    float voxel_size;
} mesh_params;

// Cube face vertices for each of the 6 faces
// Each face has 4 vertices in quad order
const vec3 face_vertices[24] = vec3[](
    // Front face (z+)
    vec3(0, 0, 1), vec3(1, 0, 1), vec3(1, 1, 1), vec3(0, 1, 1),
    // Back face (z-)
    vec3(1, 0, 0), vec3(0, 0, 0), vec3(0, 1, 0), vec3(1, 1, 0),
    // Left face (x-)
    vec3(0, 0, 0), vec3(0, 0, 1), vec3(0, 1, 1), vec3(0, 1, 0),
    // Right face (x+)
    vec3(1, 0, 1), vec3(1, 0, 0), vec3(1, 1, 0), vec3(1, 1, 1),
    // Top face (y+)
    vec3(0, 1, 1), vec3(1, 1, 1), vec3(1, 1, 0), vec3(0, 1, 0),
    // Bottom face (y-)
    vec3(0, 0, 0), vec3(1, 0, 0), vec3(1, 0, 1), vec3(0, 0, 1)
);

// Normals for each of the 6 faces
const vec3 face_normals[6] = vec3[](
    vec3(0, 0, 1),  // Front (z+)
    vec3(0, 0, -1), // Back (z-)
    vec3(-1, 0, 0), // Left (x-)
    vec3(1, 0, 0),  // Right (x+)
    vec3(0, 1, 0),  // Top (y+)
    vec3(0, -1, 0)  // Bottom (y-)
);

// UV coordinates for a quad face (0,0) (1,0) (1,1) (0,1)
const vec2 face_uvs[4] = vec2[](
    vec2(0, 0), vec2(1, 0), vec2(1, 1), vec2(0, 1)
);

// Triangle indices for each face (2 triangles)
const uint face_indices[6] = uint[](0, 1, 2, 2, 3, 0);

float get_density(ivec3 pos) {
    if (pos.x < 0 || pos.x >= int(mesh_params.chunk_size) ||
        pos.y < 0 || pos.y >= int(mesh_params.chunk_size) ||
        pos.z < 0 || pos.z >= int(mesh_params.chunk_size)) {
        return -1.0; // Outside bounds = empty
    }
    
    uint index = uint(pos.x + pos.y * int(mesh_params.chunk_size) + pos.z * int(mesh_params.chunk_size) * int(mesh_params.chunk_size));
    return voxel_data.density[index];
}

void create_face(uint face_id, ivec3 voxel_pos) {
    // Each vertex requires 3 floats for position, 3 for normal, 2 for UV = 8 floats total.
    // So, 4 vertices per face * 8 floats/vertex = 32 floats for a face.
    uint base_vertex_float_idx = atomicAdd(counter.vertex_count, 4) * 8; // Increment by 4 vertices, convert to float index
    uint base_index = atomicAdd(counter.index_count, 6);
    
    vec3 normal = face_normals[face_id];

    // Generate 4 vertices for this face
    for (uint i = 0; i < 4; i++) {
        vec3 local_vertex = face_vertices[face_id * 4 + i];
        vec3 world_vertex = (vec3(voxel_pos) + local_vertex) * mesh_params.voxel_size;
        vec2 uv = face_uvs[i];
        
        // Store vertex data: position (3), normal (3), uv (2)
        uint current_vertex_base_idx = base_vertex_float_idx + (i * 8); // Base float index for this specific vertex
        
        // Position
        vertex_data.data[current_vertex_base_idx] = world_vertex.x;
        vertex_data.data[current_vertex_base_idx + 1] = world_vertex.y;
        vertex_data.data[current_vertex_base_idx + 2] = world_vertex.z;
        
        // Normal
        vertex_data.data[current_vertex_base_idx + 3] = normal.x;
        vertex_data.data[current_vertex_base_idx + 4] = normal.y;
        vertex_data.data[current_vertex_base_idx + 5] = normal.z;

        // UV
        vertex_data.data[current_vertex_base_idx + 6] = uv.x;
        vertex_data.data[current_vertex_base_idx + 7] = uv.y;
    }
    
    // Generate 6 indices for this face (2 triangles)
    for (uint i = 0; i < 6; i++) {
        // Indices refer to the vertex *count*, not the float index
        index_data.indices[base_index + i] = (base_vertex_float_idx / 8) + face_indices[i];
    }
}

void main() {
    ivec3 voxel_pos = ivec3(gl_GlobalInvocationID.xyz);
    
    // Check bounds
    if (voxel_pos.x >= int(mesh_params.chunk_size) || 
        voxel_pos.y >= int(mesh_params.chunk_size) || 
        voxel_pos.z >= int(mesh_params.chunk_size)) {
        return;
    }
    
    // Check if this voxel is solid (positive density)
    if (get_density(voxel_pos) <= 0.0) {
        return; // Empty voxel, skip
    }
    
    // Check each face for exposure and generate mesh
    ivec3 neighbors[6] = ivec3[](
        ivec3(0, 0, 1),   // Front
        ivec3(0, 0, -1),  // Back
        ivec3(-1, 0, 0),  // Left
        ivec3(1, 0, 0),   // Right
        ivec3(0, 1, 0),   // Top
        ivec3(0, -1, 0)   // Bottom
    );
    
    for (uint face = 0; face < 6; face++) {
        ivec3 neighbor_pos = voxel_pos + neighbors[face];
        
        // Only generate face if neighbor is empty (negative or zero density)
        if (get_density(neighbor_pos) <= 0.0) {
            create_face(face, voxel_pos);
        }
    }
}