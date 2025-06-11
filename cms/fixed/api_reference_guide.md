# API Reference for Web Client Development

## Base URL
```
http://localhost:8080
```

## Authentication Flow

### 1. Register User
```javascript
const response = await fetch('/api/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'testuser',
    email: 'test@example.com',
    password: 'password123'
  })
});

const data = await response.json();
// Response: { user_id, username, token, message }
const token = data.token; // Store this for API calls
```

### 2. Login User
```javascript
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'testuser',
    password: 'password123'
  })
});

const data = await response.json();
const token = data.token; // Store in localStorage/sessionStorage
```

### 3. Authenticated Requests
```javascript
// For all authenticated requests, include:
headers: {
  'Authorization': `Bearer ${token}`
}
```

## File Upload

### Upload Single File
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const response = await fetch('/api/files/upload', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData // Don't set Content-Type, let browser set it
});

const data = await response.json();
// Response: { message, files: [{ file_id, original_filename, file_size, mime_type }] }
```

### Upload Multiple Files
```javascript
const formData = new FormData();
for (let file of fileInput.files) {
  formData.append('files', file);
}

const response = await fetch('/api/files/upload', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` },
  body: formData
});
```

## File Management

### List User Files
```javascript
const response = await fetch('/api/files?limit=20&include_public=false', {
  headers: { 'Authorization': `Bearer ${token}` }
});

const data = await response.json();
// Response: { files: [...], count }
```

### Get File Info
```javascript
const response = await fetch(`/api/files/${fileId}`, {
  headers: { 'Authorization': `Bearer ${token}` }
});

const fileInfo = await response.json();
// Response: { original_filename, file_size, mime_type, uploaded_at, downloads, ... }
```

### Download File
```javascript
const response = await fetch(`/api/files/${fileId}/download`, {
  headers: { 'Authorization': `Bearer ${token}` }
});

if (response.ok) {
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename; // Set desired filename
  a.click();
  window.URL.revokeObjectURL(url);
}
```

### Update File Metadata
```javascript
const response = await fetch(`/api/files/${fileId}`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    description: 'Updated description',
    tags: ['tag1', 'tag2'],
    is_public: true
  })
});
```

### Delete File
```javascript
const response = await fetch(`/api/files/${fileId}`, {
  method: 'DELETE',
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## File Sharing

### Create Share Link
```javascript
const response = await fetch(`/api/files/${fileId}/share`, {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` }
});

const data = await response.json();
// Response: { share_token, share_url }
const publicUrl = `${baseUrl}/api/files/share/${data.share_token}`;
```

### Public Download (No Auth Required)
```javascript
// Anyone can access this URL
const publicUrl = `/api/files/share/${shareToken}`;

// Direct link or programmatic download
const response = await fetch(publicUrl);
const blob = await response.blob();
```

### Revoke Sharing
```javascript
const response = await fetch(`/api/files/${fileId}/share`, {
  method: 'DELETE',
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## Posts & Content

### Create Post
```javascript
const response = await fetch('/api/posts', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    title: 'My Post Title',
    content: 'Post content here...',
    tags: ['tech', 'api'],
    is_published: true,
    attached_files: [fileId1, fileId2] // Optional file attachments
  })
});

const data = await response.json();
// Response: { post_id, post: {...} }
```

### List Posts
```javascript
const response = await fetch('/api/posts?limit=10&published=true');
const data = await response.json();
// Response: { posts: [...], count }
```

### Get Specific Post
```javascript
const response = await fetch(`/api/posts/${postId}`);
const post = await response.json();
// Increments view count automatically
```

### Like/Unlike Post
```javascript
// Like
const likeResponse = await fetch(`/api/posts/${postId}/like`, {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` }
});

// Unlike
const unlikeResponse = await fetch(`/api/posts/${postId}/unlike`, {
  method: 'POST', 
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## Error Handling

### Standard Error Response Format
```javascript
{
  "error": "Error message",
  "details": {} // Optional additional details
}
```

### Common Status Codes
- `200` - Success
- `201` - Created (for uploads, posts)
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (missing/invalid token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate data)
- `413` - Payload Too Large (file size limit)
- `500` - Internal Server Error

### Error Handling Example
```javascript
try {
  const response = await fetch('/api/files/upload', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });

  if (!response.ok) {
    const error = await response.json();
    console.error(`Error ${response.status}:`, error.error);
    
    // Handle specific errors
    if (response.status === 401) {
      // Redirect to login
    } else if (response.status === 413) {
      // File too large
    }
    return;
  }

  const data = await response.json();
  // Success handling
} catch (error) {
  console.error('Network error:', error);
}
```

## File Display Helpers

### Display File Size
```javascript
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
```

### Check if File is Image
```javascript
function isImage(mimeType) {
  return mimeType.startsWith('image/');
}

function canPreview(mimeType) {
  return ['image/', 'text/', 'application/pdf'].some(type => 
    mimeType.startsWith(type)
  );
}
```

### Generate Thumbnail URL (for images)
```javascript
// For image files, you can display them directly
function getImageUrl(fileId, token) {
  return `/api/files/${fileId}/download`;
}

// Example usage in img tag:
// <img src="/api/files/${fileId}/download" headers="Authorization: Bearer ${token}" />
// Note: For images in HTML, you may need to handle auth differently
```

## Real-time Features (Optional)

### Check File Upload Progress
```javascript
const xhr = new XMLHttpRequest();
xhr.upload.addEventListener('progress', (e) => {
  if (e.lengthComputable) {
    const percentComplete = (e.loaded / e.total) * 100;
    console.log(`Upload progress: ${percentComplete}%`);
  }
});

xhr.open('POST', '/api/files/upload');
xhr.setRequestHeader('Authorization', `Bearer ${token}`);
xhr.send(formData);
```

## Configuration

### API Limits (Configurable in api.py)
- Max file size: 100MB (default)
- Max files per upload: Unlimited
- Supported file types: All types
- Token expiry: 24 hours (default)

### Local Storage Management
```javascript
// Store auth token
localStorage.setItem('auth_token', token);

// Retrieve token
const token = localStorage.getItem('auth_token');

// Clear on logout
localStorage.removeItem('auth_token');
```
