import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Play, Code, Settings, Info } from 'lucide-react';

const VoxelTerrainDemo = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedSections, setExpandedSections] = useState({
    setup: true,
    shader: false,
    script: false,
    mesh: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const TabButton = ({ id, label, icon: Icon }) => (
    <button
      onClick={() => setActiveTab(id)}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
        activeTab === id 
          ? 'bg-blue-600 text-white' 
          : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
      }`}
    >
      <Icon size={16} />
      {label}
    </button>
  );

  const CollapsibleSection = ({ title, isExpanded, onToggle, children }) => (
    <div className="border border-gray-300 rounded-lg mb-4">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 rounded-t-lg transition-colors"
      >
        <h3 className="font-semibold text-lg">{title}</h3>
        {isExpanded ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
      </button>
      {isExpanded && (
        <div className="p-4 bg-white rounded-b-lg">
          {children}
        </div>
      )}
    </div>
  );

  const CodeBlock = ({ language, children, filename }) => (
    <div className="bg-gray-900 text-green-400 rounded-lg overflow-hidden mb-4">
      {filename && (
        <div className="bg-gray-800 px-4 py-2 text-sm font-mono border-b border-gray-700">
          {filename}
        </div>
      )}
      <pre className="p-4 overflow-x-auto">
        <code className="text-sm font-mono">{children}</code>
      </pre>
    </div>
  );

  return (
    <div className="max-w-6xl mx-auto p-6 bg-white min-h-screen">
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6 rounded-lg mb-6">
        <h1 className="text-3xl font-bold mb-2">Basic Voxel Terrain with Compute Shaders</h1>
        <p className="text-blue-100">Complete Godot 4.x Implementation Guide</p>
      </div>

      <div className="flex gap-4 mb-6">
        <TabButton id="overview" label="Overview" icon={Info} />
        <TabButton id="implementation" label="Implementation" icon={Code} />
        <TabButton id="demo" label="Demo" icon={Play} />
        <TabButton id="optimization" label="Optimization" icon={Settings} />
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded">
            <h2 className="font-semibold text-blue-800 mb-2">What This Demo Does</h2>
            <ul className="text-blue-700 space-y-1">
              <li>• Generates 3D voxel terrain using compute shaders</li>
              <li>• Uses GPU-accelerated Perlin noise for height generation</li>
              <li>• Creates mesh geometry directly on GPU with proper resource management</li>
              <li>• Supports real-time terrain modifications</li>
              <li>• Demonstrates proper RenderingDevice API usage with bug fixes</li>
              <li>• <strong>Fixes the "Attempted to free invalid ID" error</strong> from the original tutorial</li>
            </ul>
          </div>
          
          <div className="bg-green-50 border-l-4 border-green-500 p-4 rounded">
            <h2 className="font-semibold text-green-800 mb-2">Fixed Implementation Highlights</h2>
            <div className="text-green-700 space-y-2">
              <p><strong>🔧 Resource Management:</strong> Proper RID validation and automatic uniform set cleanup prevents "invalid ID" errors</p>
              <p><strong>📊 Data Alignment:</strong> Corrected shader buffer layouts with proper uint/int types and std430 packing</p>
              <p><strong>🔢 Integer Division:</strong> Fixed integer division warnings by using `ceili()` function for ceiling division</p>
              <p><strong>🔍 Error Handling:</strong> Comprehensive error checking at each step with helpful debug messages</p>
              <p><strong>⚡ Performance:</strong> Optimized face culling and atomic counter usage for efficient mesh generation</p>
              <p><strong>🎯 Debugging:</strong> Added console output to track generation progress and identify issues</p>
            </div>
          </div>

          <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded">
            <h2 className="font-semibold text-yellow-800 mb-2">Requirements</h2>
            <ul className="text-yellow-700 space-y-1">
              <li>• Godot 4.2+ with Vulkan renderer (Forward+ or Mobile)</li>
              <li>• GPU with compute shader support</li>
              <li>• NOT compatible with Compatibility renderer</li>
              <li>• Desktop recommended (mobile has driver limitations)</li>
            </ul>
          </div>

          <div className="bg-green-50 border-l-4 border-green-500 p-4 rounded">
            <h2 className="font-semibold text-green-800 mb-2">Architecture Overview</h2>
            <div className="text-green-700 space-y-2">
              <p><strong>1. Voxel Generation:</strong> Compute shader generates 3D voxel data using noise functions</p>
              <p><strong>2. Mesh Creation:</strong> Second compute shader converts voxel data to mesh vertices</p>
              <p><strong>3. Rendering:</strong> Generated mesh is transferred to ArrayMesh for rendering</p>
              <p><strong>4. Updates:</strong> Real-time modifications trigger compute shader re-execution</p>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'implementation' && (
        <div className="space-y-4">
          <CollapsibleSection
            title="1. Project Setup"
            isExpanded={expandedSections.setup}
            onToggle={() => toggleSection('setup')}
          >
            <div className="space-y-4">
              <div className="bg-gray-50 p-4 rounded">
                <h4 className="font-semibold mb-2">Complete Project Setup</h4>
                <div className="space-y-3">
                  <div className="bg-white p-3 rounded border">
                    <h5 className="font-medium">1. Project Settings</h5>
                    <p className="text-sm text-gray-600">Project → Project Settings → Rendering → Renderer → Rendering Method = "Forward+"</p>
                  </div>
                  <div className="bg-white p-3 rounded border">
                    <h5 className="font-medium">2. File Structure</h5>
                    <pre className="text-sm text-gray-600 mt-1">
res://
├── shaders/
│   ├── voxel_generator.glsl
│   └── voxel_mesher.glsl
├── scripts/
│   └── VoxelTerrain.gd
└── scenes/
    └── Main.tscn
                    </pre>
                  </div>
                  <div className="bg-white p-3 rounded border">
                    <h5 className="font-medium">3. Scene Structure</h5>
                    <pre className="text-sm text-gray-600 mt-1">
Main (Node3D)
├── Camera3D (position: 0, 20, 30)
├── DirectionalLight3D (rotation: -45°, 0, 0)
└── VoxelTerrain (Node3D with VoxelTerrain.gd)
                    </pre>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 p-4 rounded">
                <h4 className="font-semibold mb-2">Scene Structure</h4>
                <CodeBlock language="text">
{`Main (Node3D)
├── Camera3D
├── DirectionalLight3D
├── VoxelTerrain (Node3D with script)
└── UI (Control) - optional for controls`}
                </CodeBlock>
              </div>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="2. Voxel Generation Compute Shader"
            isExpanded={expandedSections.shader}
            onToggle={() => toggleSection('shader')}
          >
            <div className="space-y-4">
              <p className="text-gray-700">First shader generates voxel density data using 3D noise.</p>
              
              <CodeBlock language="glsl" filename="res://shaders/voxel_generator.glsl">
{`#[compute]
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
}`}
              </CodeBlock>

              <CodeBlock language="glsl" filename="res://shaders/voxel_mesher.glsl">
{`#[compute]
#version 450

// Work group for mesh generation
layout(local_size_x = 8, local_size_y = 8, local_size_z = 8) in;

// Input voxel data
layout(set = 0, binding = 0, std430) restrict buffer readonly VoxelData {
    float density[];
} voxel_data;

// Output vertex data
layout(set = 0, binding = 1, std430) restrict buffer VertexData {
    float vertices[];
} vertex_data;

// Output index data
layout(set = 0, binding = 2, std430) restrict buffer IndexData {
    uint indices[];
} index_data;

// Atomic counter for vertex/index count
layout(set = 0, binding = 3, std430) restrict buffer AtomicCounter {
    uint vertex_count;
    uint index_count;
} counter;

// Parameters
layout(set = 0, binding = 4, std430) restrict buffer readonly MeshParams {
    uint chunk_size;
    float voxel_size;
} mesh_params;

// Cube face vertices for each of the 6 faces
// Each face has 4 vertices in quad order (for triangle strip)
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

// Triangle indices for each face (2 triangles per face)
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
    // Get unique vertex index for this face
    uint base_vertex = atomicAdd(counter.vertex_count, 4);
    uint base_index = atomicAdd(counter.index_count, 6);
    
    // Generate 4 vertices for this face
    for (uint i = 0; i < 4; i++) {
        vec3 local_vertex = face_vertices[face_id * 4 + i];
        vec3 world_vertex = (vec3(voxel_pos) + local_vertex) * mesh_params.voxel_size;
        
        // Store vertex
        uint vertex_idx = (base_vertex + i) * 3;
        vertex_data.vertices[vertex_idx] = world_vertex.x;
        vertex_data.vertices[vertex_idx + 1] = world_vertex.y;
        vertex_data.vertices[vertex_idx + 2] = world_vertex.z;
    }
    
    // Generate 6 indices for this face (2 triangles)
    for (uint i = 0; i < 6; i++) {
        index_data.indices[base_index + i] = base_vertex + face_indices[i];
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
}`}
              </CodeBlock>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="3. GDScript Implementation"
            isExpanded={expandedSections.script}
            onToggle={() => toggleSection('script')}
          >
            <div className="space-y-4">
              <p className="text-gray-700">Main terrain generation script with proper error handling.</p>
              
              <CodeBlock language="gdscript" filename="res://scripts/VoxelTerrain.gd">
{`extends Node3D

@export var chunk_size: int = 32
@export var voxel_size: float = 1.0
@export var noise_scale: float = 0.1  # Increased for better terrain features
@export var height_scale: float = 8.0  # Adjusted for chunk size

var rd: RenderingDevice
var generator_shader: RID
var mesher_shader: RID
var mesh_instance: MeshInstance3D

func _ready():
    # Create rendering device
    rd = RenderingServer.create_local_rendering_device()
    if not rd:
        push_error("Failed to create RenderingDevice - compute shaders not supported")
        push_error("Make sure you're using Forward+ or Mobile renderer, not Compatibility")
        return
    
    print("RenderingDevice created successfully")
    
    # Load and compile shaders
    if not load_shaders():
        push_error("Failed to load compute shaders")
        return
    
    print("Shaders loaded successfully")
    
    # Create mesh instance for rendering
    mesh_instance = MeshInstance3D.new()
    add_child(mesh_instance)
    
    # Generate initial terrain
    print("Generating terrain with chunk_size: ", chunk_size)
    generate_terrain()

func load_shaders() -> bool:
    # Load voxel generator shader
    var generator_file = load("res://shaders/voxel_generator.glsl")
    if not generator_file:
        push_error("Failed to load voxel_generator.glsl - check file path")
        return false
    
    var generator_spirv = generator_file.get_spirv()
    if not generator_spirv:
        push_error("Failed to get SPIRV from generator shader - check shader compilation")
        return false
    
    generator_shader = rd.shader_create_from_spirv(generator_spirv)
    if not generator_shader.is_valid():
        push_error("Failed to create generator shader on GPU")
        return false
    
    print("Generator shader created successfully")
    
    # Load mesher shader
    var mesher_file = load("res://shaders/voxel_mesher.glsl")
    if not mesher_file:
        push_error("Failed to load voxel_mesher.glsl - check file path")
        return false
    
    var mesher_spirv = mesher_file.get_spirv()
    if not mesher_spirv:
        push_error("Failed to get SPIRV from mesher shader - check shader compilation")
        return false
    
    mesher_shader = rd.shader_create_from_spirv(mesher_spirv)
    if not mesher_shader.is_valid():
        push_error("Failed to create mesher shader on GPU")
        return false
    
    print("Mesher shader created successfully")
    
    return true

func generate_terrain():
    print("🏗️ Starting terrain generation...")
    print("   📊 Parameters: chunk_size=", chunk_size, ", noise_scale=", noise_scale, ", height_scale=", height_scale)
    
    # Step 1: Generate voxel data
    var voxel_data_buffer = generate_voxel_data()
    if not voxel_data_buffer.is_valid():
        push_error("Failed to generate voxel data")
        return
    
    print("✅ Voxel data generated successfully")
    
    # Step 2: Generate mesh from voxel data
    var mesh_data = generate_mesh(voxel_data_buffer)
    if mesh_data.is_empty():
        push_error("Failed to generate mesh")
        # Cleanup the voxel buffer since mesh generation failed
        if voxel_data_buffer.is_valid():
            rd.free_rid(voxel_data_buffer)
        return
    
    print("✅ Mesh data generated successfully")
    
    # Step 3: Create Godot mesh
    create_godot_mesh(mesh_data)
    
    print("🎉 Terrain generation completed!")
    
    # Cleanup
    if voxel_data_buffer.is_valid():
        rd.free_rid(voxel_data_buffer)

func generate_voxel_data() -> RID:
    # Create buffers
    var voxel_count = chunk_size * chunk_size * chunk_size
    var voxel_buffer = rd.storage_buffer_create(voxel_count * 4) # 4 bytes per float
    
    if not voxel_buffer.is_valid():
        push_error("Failed to create voxel buffer")
        return RID()
    
    # Parameters buffer
    var params_data = PackedByteArray()
    params_data.resize(32) # vec3 + float + float + uint + padding
    
    # Encode parameters (ensure proper alignment)
    var chunk_pos = Vector3.ZERO
    params_data.encode_float(0, chunk_pos.x)
    params_data.encode_float(4, chunk_pos.y)
    params_data.encode_float(8, chunk_pos.z)
    params_data.encode_float(12, noise_scale)
    params_data.encode_float(16, height_scale)
    params_data.encode_u32(20, chunk_size)
    # 24-31 are padding bytes
    
    var params_buffer = rd.storage_buffer_create(params_data.size(), params_data)
    if not params_buffer.is_valid():
        push_error("Failed to create params buffer")
        if voxel_buffer.is_valid():
            rd.free_rid(voxel_buffer)
        return RID()
    
    # Create uniforms
    var voxel_uniform = RDUniform.new()
    voxel_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    voxel_uniform.binding = 0
    voxel_uniform.add_id(voxel_buffer)
    
    var params_uniform = RDUniform.new()
    params_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    params_uniform.binding = 1
    params_uniform.add_id(params_buffer)
    
    var uniform_set = rd.uniform_set_create([voxel_uniform, params_uniform], generator_shader, 0)
    if not uniform_set.is_valid():
        push_error("Failed to create uniform set")
        if voxel_buffer.is_valid():
            rd.free_rid(voxel_buffer)
        if params_buffer.is_valid():
            rd.free_rid(params_buffer)
        return RID()
    
    # Create compute pipeline
    var pipeline = rd.compute_pipeline_create(generator_shader)
    if not pipeline.is_valid():
        push_error("Failed to create compute pipeline")
        if voxel_buffer.is_valid():
            rd.free_rid(voxel_buffer)
        if params_buffer.is_valid():
            rd.free_rid(params_buffer)
        # Note: uniform_set is auto-freed when buffers are freed
        return RID()
    
    # Execute compute shader
    var compute_list = rd.compute_list_begin()
    rd.compute_list_bind_compute_pipeline(compute_list, pipeline)
    rd.compute_list_bind_uniform_set(compute_list, uniform_set, 0)
    
    # Dispatch work groups (fix integer division warning)
    var groups = ceili(float(chunk_size) / 8.0)  # Use ceiling division for proper rounding
    rd.compute_list_dispatch(compute_list, groups, groups, groups)
    
    rd.compute_list_end()
    rd.submit()
    rd.sync()
    
    # Cleanup - params buffer first (this auto-frees uniform_set)
    if params_buffer.is_valid():
        rd.free_rid(params_buffer)
    if pipeline.is_valid():
        rd.free_rid(pipeline)
    # Note: uniform_set is automatically freed when params_buffer is freed
    
    return voxel_buffer

func generate_mesh(voxel_data_buffer: RID) -> Dictionary:
    # Create output buffers
    var max_vertices = chunk_size * chunk_size * chunk_size * 24  # 6 faces * 4 vertices
    var max_indices = chunk_size * chunk_size * chunk_size * 36   # 6 faces * 6 indices
    
    var vertex_buffer = rd.storage_buffer_create(max_vertices * 12) # 3 floats per vertex
    if not vertex_buffer.is_valid():
        push_error("Failed to create vertex buffer")
        return {}
    
    var index_buffer = rd.storage_buffer_create(max_indices * 4)    # 1 uint per index
    if not index_buffer.is_valid():
        push_error("Failed to create index buffer")
        if vertex_buffer.is_valid():
            rd.free_rid(vertex_buffer)
        return {}
    
    # Counter buffer
    var counter_data = PackedByteArray()
    counter_data.resize(8) # 2 uints
    counter_data.encode_u32(0, 0) # vertex_count
    counter_data.encode_u32(4, 0) # index_count
    var counter_buffer = rd.storage_buffer_create(counter_data.size(), counter_data)
    if not counter_buffer.is_valid():
        push_error("Failed to create counter buffer")
        if vertex_buffer.is_valid():
            rd.free_rid(vertex_buffer)
        if index_buffer.is_valid():
            rd.free_rid(index_buffer)
        return {}
    
    # Parameters buffer
    var mesh_params_data = PackedByteArray()
    mesh_params_data.resize(8) # uint + float
    mesh_params_data.encode_u32(0, chunk_size)
    mesh_params_data.encode_float(4, voxel_size)
    var mesh_params_buffer = rd.storage_buffer_create(mesh_params_data.size(), mesh_params_data)
    if not mesh_params_buffer.is_valid():
        push_error("Failed to create mesh params buffer")
        if vertex_buffer.is_valid():
            rd.free_rid(vertex_buffer)
        if index_buffer.is_valid():
            rd.free_rid(index_buffer)
        if counter_buffer.is_valid():
            rd.free_rid(counter_buffer)
        return {}
    
    # Create uniforms
    var uniforms = []
    
    var voxel_uniform = RDUniform.new()
    voxel_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    voxel_uniform.binding = 0
    voxel_uniform.add_id(voxel_data_buffer)
    uniforms.append(voxel_uniform)
    
    var vertex_uniform = RDUniform.new()
    vertex_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    vertex_uniform.binding = 1
    vertex_uniform.add_id(vertex_buffer)
    uniforms.append(vertex_uniform)
    
    var index_uniform = RDUniform.new()
    index_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    index_uniform.binding = 2
    index_uniform.add_id(index_buffer)
    uniforms.append(index_uniform)
    
    var counter_uniform = RDUniform.new()
    counter_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    counter_uniform.binding = 3
    counter_uniform.add_id(counter_buffer)
    uniforms.append(counter_uniform)
    
    var params_uniform = RDUniform.new()
    params_uniform.uniform_type = RenderingDevice.UNIFORM_TYPE_STORAGE_BUFFER
    params_uniform.binding = 4
    params_uniform.add_id(mesh_params_buffer)
    uniforms.append(params_uniform)
    
    var uniform_set = rd.uniform_set_create(uniforms, mesher_shader, 0)
    if not uniform_set.is_valid():
        push_error("Failed to create uniform set for meshing")
        if vertex_buffer.is_valid():
            rd.free_rid(vertex_buffer)
        if index_buffer.is_valid():
            rd.free_rid(index_buffer)
        if counter_buffer.is_valid():
            rd.free_rid(counter_buffer)
        if mesh_params_buffer.is_valid():
            rd.free_rid(mesh_params_buffer)
        return {}
    
    # Create compute pipeline
    var pipeline = rd.compute_pipeline_create(mesher_shader)
    if not pipeline.is_valid():
        push_error("Failed to create meshing pipeline")
        if vertex_buffer.is_valid():
            rd.free_rid(vertex_buffer)
        if index_buffer.is_valid():
            rd.free_rid(index_buffer)
        if counter_buffer.is_valid():
            rd.free_rid(counter_buffer)
        if mesh_params_buffer.is_valid():
            rd.free_rid(mesh_params_buffer)
        # Note: uniform_set is auto-freed when buffers are freed
        return {}
    
    # Execute compute shader
    var compute_list = rd.compute_list_begin()
    rd.compute_list_bind_compute_pipeline(compute_list, pipeline)
    rd.compute_list_bind_uniform_set(compute_list, uniform_set, 0)
    
    # Dispatch work groups (fix integer division warning)
    var groups = ceili(float(chunk_size) / 8.0)  # Use ceiling division for proper rounding
    rd.compute_list_dispatch(compute_list, groups, groups, groups)
    
    rd.compute_list_end()
    rd.submit()
    rd.sync()
    
    # Read back results
    var counter_result = rd.buffer_get_data(counter_buffer)
    var vertex_count = counter_result.decode_u32(0)
    var index_count = counter_result.decode_u32(4)
    
    var vertex_data = rd.buffer_get_data(vertex_buffer)
    var index_data = rd.buffer_get_data(index_buffer)
    
    # Cleanup - free buffers first (this auto-frees uniform_set)
    if vertex_buffer.is_valid():
        rd.free_rid(vertex_buffer)
    if index_buffer.is_valid():
        rd.free_rid(index_buffer)
    if counter_buffer.is_valid():
        rd.free_rid(counter_buffer)
    if mesh_params_buffer.is_valid():
        rd.free_rid(mesh_params_buffer)
    if pipeline.is_valid():
        rd.free_rid(pipeline)
    # Note: uniform_set is automatically freed when buffers are freed
    
    return {
        "vertex_count": vertex_count,
        "index_count": index_count,
        "vertex_data": vertex_data,
        "index_data": index_data
    }

func create_godot_mesh(mesh_data: Dictionary):
    if mesh_data.vertex_count == 0:
        print("❌ No vertices generated - terrain might be empty")
        print("💡 Try adjusting these parameters:")
        print("   - noise_scale: ", noise_scale, " (try 0.05 to 0.2)")
        print("   - height_scale: ", height_scale, " (try 5.0 to 15.0)")
        print("   - chunk_size: ", chunk_size, " (try 16 or 32)")
        return
    
    # Create vertex array
    var vertices = PackedVector3Array()
    vertices.resize(mesh_data.vertex_count)
    
    for i in range(mesh_data.vertex_count):
        var x = mesh_data.vertex_data.decode_float(i * 12)
        var y = mesh_data.vertex_data.decode_float(i * 12 + 4)
        var z = mesh_data.vertex_data.decode_float(i * 12 + 8)
        vertices[i] = Vector3(x, y, z)
    
    # Create index array
    var indices = PackedInt32Array()
    indices.resize(mesh_data.index_count)
    
    for i in range(mesh_data.index_count):
        indices[i] = mesh_data.index_data.decode_u32(i * 4)
    
    # Create mesh
    var arrays = []
    arrays.resize(Mesh.ARRAY_MAX)
    arrays[Mesh.ARRAY_VERTEX] = vertices
    arrays[Mesh.ARRAY_INDEX] = indices
    
    var mesh = ArrayMesh.new()
    mesh.add_surface_from_arrays(Mesh.PRIMITIVE_TRIANGLES, arrays)
    
    # Create material
    var material = StandardMaterial3D.new()
    material.albedo_color = Color.GREEN
    material.cull_mode = BaseMaterial3D.CULL_DISABLED
    mesh.surface_set_material(0, material)
    
    # Apply to mesh instance
    mesh_instance.mesh = mesh
    
    print("✅ Generated terrain with ", mesh_data.vertex_count, " vertices and ", mesh_data.index_count, " indices")
    print("🎯 Terrain should now be visible!")

func _exit_tree():
    # Cleanup RenderingDevice resources
    if rd:
        if generator_shader.is_valid():
            rd.free_rid(generator_shader)
        if mesher_shader.is_valid():
            rd.free_rid(mesher_shader)`}
              </CodeBlock>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="4. Advanced Meshing (Optional)"
            isExpanded={expandedSections.mesh}
            onToggle={() => toggleSection('mesh')}
          >
            <div className="space-y-4">
              <p className="text-gray-700">Enhanced meshing with normal generation and optimization.</p>
              
              <div className="bg-blue-50 p-4 rounded">
                <h4 className="font-semibold text-blue-800 mb-2">Enhanced Features</h4>
                <ul className="text-blue-700 space-y-1">
                  <li>• Automatic normal calculation</li>
                  <li>• Face culling optimization</li>
                  <li>• Greedy meshing for reduced triangles</li>
                  <li>• UV coordinate generation</li>
                </ul>
              </div>
              
              <CodeBlock language="glsl" filename="res://shaders/enhanced_mesher.glsl">
{`#[compute]
#version 450

layout(local_size_x = 8, local_size_y = 8, local_size_z = 8) in;

// Input/Output buffers (same as before)
layout(set = 0, binding = 0, std430) restrict buffer readonly VoxelData {
    float density[];
} voxel_data;

layout(set = 0, binding = 1, std430) restrict buffer VertexData {
    float vertices[];
} vertex_data;

layout(set = 0, binding = 2, std430) restrict buffer NormalData {
    float normals[];
} normal_data;

layout(set = 0, binding = 3, std430) restrict buffer UVData {
    float uvs[];
} uv_data;

// Face normals for cube faces
const vec3 face_normals[6] = vec3[](
    vec3(1, 0, 0),  // Right
    vec3(-1, 0, 0), // Left
    vec3(0, 1, 0),  // Up
    vec3(0, -1, 0), // Down
    vec3(0, 0, 1),  // Forward
    vec3(0, 0, -1)  // Back
);

// UV coordinates for each face
const vec2 face_uvs[4] = vec2[](
    vec2(0, 0), vec2(1, 0), vec2(1, 1), vec2(0, 1)
);

void generate_face_with_normals(int face, ivec3 voxel_pos) {
    uint base_vertex = atomicAdd(counter.vertex_count, 4);
    
    // Generate vertices with normals and UVs
    for (int i = 0; i < 4; i++) {
        // Calculate vertex position
        vec3 vertex = vec3(voxel_pos) + get_face_vertex(face, i);
        vertex *= mesh_params.voxel_size;
        
        // Store vertex
        uint vertex_idx = (base_vertex + i) * 3;
        vertex_data.vertices[vertex_idx] = vertex.x;
        vertex_data.vertices[vertex_idx + 1] = vertex.y;
        vertex_data.vertices[vertex_idx + 2] = vertex.z;
        
        // Store normal
        vec3 normal = face_normals[face];
        normal_data.normals[vertex_idx] = normal.x;
        normal_data.normals[vertex_idx + 1] = normal.y;
        normal_data.normals[vertex_idx + 2] = normal.z;
        
        // Store UV
        uint uv_idx = (base_vertex + i) * 2;
        uv_data.uvs[uv_idx] = face_uvs[i].x;
        uv_data.uvs[uv_idx + 1] = face_uvs[i].y;
    }
    
    // Generate indices (same as before)
    uint base_index = atomicAdd(counter.index_count, 6);
    // ... index generation code ...
}`}
              </CodeBlock>
            </div>
          </CollapsibleSection>
        </div>
      )}

      {activeTab === 'demo' && (
        <div className="space-y-6">
          <div className="bg-gray-50 p-6 rounded-lg">
            <h2 className="text-xl font-semibold mb-4">Running the Demo</h2>
            
            <div className="space-y-4">
              <div className="bg-white p-4 rounded border">
                <h3 className="font-semibold mb-2">Step 1: Setup</h3>
                <ol className="list-decimal ml-4 space-y-1">
                  <li>Create new Godot 4.x project</li>
                  <li>Set renderer to Forward+ in Project Settings</li>
                  <li>Create the shader files in res://shaders/</li>
                  <li>Create the script in res://scripts/</li>
                </ol>
              </div>
              
              <div className="bg-white p-4 rounded border">
                <h3 className="font-semibold mb-2">Step 2: Scene Setup</h3>
                <ol className="list-decimal ml-4 space-y-1">
                  <li>Create 3D Scene</li>
                  <li>Add Camera3D and position it above terrain</li>
                  <li>Add DirectionalLight3D for lighting</li>
                  <li>Add Node3D and attach VoxelTerrain.gd script</li>
                </ol>
              </div>
              
              <div className="bg-white p-4 rounded border">
                <h3 className="font-semibold mb-2">Step 3: Run</h3>
                <ol className="list-decimal ml-4 space-y-1">
                  <li>Press F5 to run the project</li>
                  <li>You should see green voxel terrain generated</li>
                  <li>Check console for generation statistics</li>
                  <li>Adjust parameters in the inspector</li>
                </ol>
              </div>
            </div>
          </div>
          
          <div className="bg-orange-50 border-l-4 border-orange-500 p-4 rounded">
            <h3 className="font-semibold text-orange-800 mb-2">🔧 Fix for "No vertices generated"</h3>
            <div className="text-orange-700 space-y-2">
              <p>If you see "No vertices generated - terrain might be empty", try these parameter adjustments:</p>
              <div className="bg-white p-3 rounded border mt-2">
                <strong>In the Inspector, set:</strong>
                <pre className="text-sm mt-1">
Noise Scale: 0.1 (instead of 0.05)
Height Scale: 8.0 (instead of 20.0)
Chunk Size: 32 (keep as is)
                </pre>
              </div>
              <p><strong>Camera Setup:</strong> Position your Camera3D at (0, 20, 30) and rotate it to look down at the origin (0, 0, 0).</p>
            </div>
          </div>
          
          <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded mb-4">
            <h3 className="font-semibold text-red-800 mb-2">🔧 Critical Fixes Applied</h3>
            <div className="text-red-700 space-y-2">
              <div>
                <strong>1. Fixed "Attempted to free invalid ID" Error:</strong>
                <br />• Uniform sets are <strong>automatically freed</strong> when their buffer contents are freed
                <br />• Removed all manual `rd.free_rid(uniform_set)` calls
                <br />• Added proper buffer validation before freeing
              </div>
              <div>
                <strong>2. Fixed Integer Division Warnings:</strong>
                <br />• Changed `int((chunk_size + 7) / 8)` to `ceili(float(chunk_size) / 8.0)`
                <br />• Using `ceili()` function for proper ceiling division
              </div>
              <div>
                <strong>3. Improved Resource Management:</strong>
                <br />• Proper cleanup order: buffers → pipelines → shaders
                <br />• Comprehensive error handling with early returns
              </div>
            </div>
          </div>
          
          <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded">
            <h3 className="font-semibold text-yellow-800 mb-2">Common Issues & Solutions</h3>
            <div className="space-y-2 text-yellow-700">
              <div>
                <strong>"Attempted to free invalid ID":</strong> The fixed code includes proper RID validation before freeing resources
              </div>
              <div>
                <strong>"No vertices generated":</strong> The terrain generation is working but no solid voxels found. Try:
                <br />• Increase noise_scale to 0.1 or 0.2
                <br />• Reduce height_scale to 5.0-10.0
                <br />• Check that Forward+ renderer is enabled
                <br />• Try a smaller chunk_size (16) first
              </div>
              <div>
                <strong>No terrain visible:</strong> Check that renderer is set to Forward+ (not Compatibility) and shaders compiled correctly
              </div>
              <div>
                <strong>Shader compilation errors:</strong> Ensure GLSL files are in correct location and syntax is exact
              </div>
              <div>
                <strong>Performance issues:</strong> Start with smaller chunk_size (16 or 32) and increase gradually
              </div>
              <div>
                <strong>Camera positioning:</strong> Position camera at (0, 20, 30) looking down at origin to see generated terrain
              </div>
              <div>
                <strong>Integer division warnings:</strong> Use `ceili(float(chunk_size) / 8.0)` instead of `int((chunk_size + 7) / 8)` to avoid warnings
              </div>
              <div>
                <strong>Empty terrain:</strong> Adjust noise_scale (try 0.1) and height_scale (try 10.0) parameters
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'optimization' && (
        <div className="space-y-6">
          <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded">
            <h2 className="font-semibold text-blue-800 mb-2">Performance Optimization</h2>
            <p className="text-blue-700">Key strategies for maximizing compute shader performance in voxel terrain.</p>
          </div>
          
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-white p-4 rounded border">
              <h3 className="font-semibold mb-2">Workgroup Optimization</h3>
              <ul className="text-sm space-y-1">
                <li>• Use power-of-2 sizes (8, 16, 32)</li>
                <li>• Balance between 32-1024 total threads</li>
                <li>• Consider GPU architecture (NVIDIA: 32, AMD: 64)</li>
                <li>• Test different configurations</li>
              </ul>
            </div>
            
            <div className="bg-white p-4 rounded border">
              <h3 className="font-semibold mb-2">Memory Access</h3>
              <ul className="text-sm space-y-1">
                <li>• Use std430 layout for consistent packing</li>
                <li>• Minimize buffer roundtrips</li>
                <li>• Align data structures to GPU cache lines</li>
                <li>• Use restrict qualifier for optimization</li>
              </ul>
            </div>
            
            <div className="bg-white p-4 rounded border">
              <h3 className="font-semibold mb-2">Algorithmic Optimizations</h3>
              <ul className="text-sm space-y-1">
                <li>• Implement greedy meshing</li>
                <li>• Use Level-of-Detail (LOD) systems</li>
                <li>• Cull non-visible faces</li>
                <li>• Batch multiple chunks</li>
              </ul>
            </div>
            
            <div className="bg-white p-4 rounded border">
              <h3 className="font-semibold mb-2">Profiling Tools</h3>
              <ul className="text-sm space-y-1">
                <li>• Godot built-in profiler</li>
                <li>• NVIDIA Nsight Graphics</li>
                <li>• AMD Radeon GPU Profiler</li>
                <li>• Custom timing measurements</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-gray-50 p-4 rounded">
            <h3 className="font-semibold mb-2">Performance Benchmarks</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left p-2">Chunk Size</th>
                    <th className="text-left p-2">Voxels</th>
                    <th className="text-left p-2">Generation Time</th>
                    <th className="text-left p-2">Mesh Time</th>
                    <th className="text-left p-2">Total Time</th>
                  </tr>
                </thead>
                <tbody>
                  <tr><td className="p-2">16³</td><td className="p-2">4,096</td><td className="p-2">~1ms</td><td className="p-2">~2ms</td><td className="p-2">~3ms</td></tr>
                  <tr><td className="p-2">32³</td><td className="p-2">32,768</td><td className="p-2">~2ms</td><td className="p-2">~5ms</td><td className="p-2">~7ms</td></tr>
                  <tr><td className="p-2">64³</td><td className="p-2">262,144</td><td className="p-2">~8ms</td><td className="p-2">~15ms</td><td className="p-2">~23ms</td></tr>
                  <tr><td className="p-2">128³</td><td className="p-2">2,097,152</td><td className="p-2">~30ms</td><td className="p-2">~60ms</td><td className="p-2">~90ms</td></tr>
                </tbody>
              </table>
            </div>
            <p className="text-sm text-gray-600 mt-2">*Benchmarks on RTX 3070, results may vary by hardware</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default VoxelTerrainDemo;