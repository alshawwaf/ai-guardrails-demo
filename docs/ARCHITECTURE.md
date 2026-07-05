# Architecture Documentation

## Overview

The AI Guardrails Demo is a Flask application with a vanilla-JavaScript frontend built from ES6 modules. The frontend uses a single module entry point (`static/js/main.js`) that page-detects and dynamically imports the relevant page module (code-splitting).

## File Organization

### JavaScript Modules (`/static/js/`)

```
static/js/
├── shared/                    # Shared utilities and components
│   ├── utils.js              # Centralized helpers
│   └── traffic-flow.js       # Traffic flow visualization
├── pages/                     # Page-specific modules
│   ├── playground.js         # Playground functionality
│   ├── dashboard.js          # Dashboard charts
│   ├── benchmarking.js       # Multi-vendor benchmarking
│   ├── settings.js           # Settings page
│   └── logs.js               # Logs table logic
└── main.js                   # Application entry point
```

#### Shared Modules

**`shared/utils.js`**
- `getAttackColor(attackType)` - Maps attack types to color codes (27 types)
- `setLoading(isLoading, btn)` - Manages button loading states

**`shared/traffic-flow.js`**
- `displayResults(data)` - Renders analysis results in modal
- `renderTrafficFlow(data, useGuardrails, useGuardrailsOutbound)` - Creates traffic flow diagram
- `showStepDetails(stepId, data)` - Shows details pane for flow steps

Creates interactive flow: **User → Inbound → LLM → Outbound → User Response**

#### Page Modules

**`pages/playground.js`**
- Prompt input handling
- LLM provider/model selection
- Batch testing runner
- Example library management

**`pages/dashboard.js`**
- Chart.js integration
- Real-time metrics display
- PDF export functionality
- Auto-refresh logic

**`pages/logs.js`**
- Table rendering
- Filtering and pagination
- CSV/JSON export
- Modal drill-down

#### Main Entry Point

**`main.js`**
- Page detection and routing
- Dynamic module loading (code-splitting)
- Mobile menu handling
- Global exports for backward compatibility

```javascript
// Example: Dynamic Import
if (document.getElementById("prompt")) {
    import('./pages/playground.js').then(module => {
        module.initPlayground();
    });
}
```

### CSS Organization (`/static/css/`)

```
static/css/
├── base/                   # Foundation styles
│   ├── variables.css      # CSS custom properties
│   ├── reset.css          # Global resets
│   ├── typography.css     # Type scale
│   └── layout.css         # Layout structure
├── components/             # Reusable components
│   ├── traffic-flow.css   # Traffic flow diagram
│   ├── modals.css         # Modal dialogs
│   ├── cards.css          # Card components
│   ├── buttons.css        # Button styles
│   ├── inputs.css         # Form controls
│   ├── comparison.css     # Benchmark comparison view
│   ├── notifications.css  # Toasts / alerts
│   ├── loaders.css        # Loading states
│   └── tables.css         # Table styles
├── pages/                  # Page-specific styles
│   ├── playground.css     # Playground page
│   ├── dashboard.css      # Dashboard page
│   ├── benchmarking.css   # Benchmarking page
│   ├── settings.css       # Settings page
│   └── logs.css           # Logs page
└── main.css                # Import orchestrator
```

The stylesheet is fully split into `base`, `components`, and `pages` and assembled via `main.css`.

## Module System

### ES6 Modules

**Exports:**
```javascript
// Named exports
export function utilityFunction() { ... }
export const CONSTANT = value;

// Default export
export default MainComponent;
```

**Imports:**
```javascript
// Named imports
import { utilityFunction, CONSTANT } from './utils.js';

// Default import
import MainComponent from './component.js';

// Dynamic import (code-splitting)
import('./module.js').then(module => { ... });
```

### Script Loading

Templates load a single ES-module entry point; there is no legacy monolithic script:

```html
<!-- Modular system (page-detects and dynamically imports page modules) -->
<script type="module" src="{{ url_for('static', filename='js/main.js') }}?v=2"></script>
```

Chart.js is loaded separately from a CDN for the dashboard/benchmarking charts.

## Traffic Flow Visualization

### Architecture

Interactive flow diagram showing request/response pipeline:

```
[User] → [Inbound Scan] → [LLM] → [Outbound Scan] → [User Response]
```

**Status Colors:**
- **Green (success)**: Scan passed
- **Red (danger)**: Threat detected, blocked
- **Gray (skipped)**: Step not executed
- **White (neutral)**: Scan disabled

**Interactive Features:**
- Click any step to view details
- Arrows color-coded based on status
- Details pane with JSON data
- Copy/close controls

### Implementation

Located in `shared/traffic-flow.js`:

1. **`renderTrafficFlow()`** - Generates HTML structure
2. **`createStep()`** - Helper for step elements
3. **`createArrow()`** - Helper for arrow elements
4. **`showStepDetails()`** - Displays step information

**Conditional Rendering:**
- Outbound step only shown if enabled
- Arrows adapt to active scan configuration
- User Response step shows delivery status

## Data Flow

### 1. User Input → Backend

```
Playground → POST /api/analyze → Flask Route
```

**Payload:**
```json
{
  "prompt": "user input",
  "use_guardrails": true,
  "use_guardrails_outbound": true,
  "model_provider": "openai",
  "model_name": "gpt-4"
}
```

### 2. Backend Processing

```
Flask → AI Guardrails Inbound → OpenAI/Azure → AI Guardrails Outbound → Response
```

**Database Storage:**
- Request/response logged to SQLite
- Attack vectors stored separately (inbound/outbound)
- Timestamps and metadata captured

### 3. Response → Frontend

```javascript
// Response structure
{
  "flagged": boolean,
  "guardrails_result": {...},
  "openai_response": "...",
  "guardrails_outbound_result": {...},
  "model_provider": "openai"
}
```

**Rendering:**
- `displayResults()` called
- Traffic flow diagram generated
- Attack vectors displayed as cards
- Modal shown with all details

## State Management

### Local Storage
- LLM provider preference
- Model selection
- User preferences

### In-Memory
- Active logs (dashboard feed)
- Chart data cache
- Filter states

### Database (SQLite)
- API credentials (settings)
- Scan history
- Attack vector records

## Performance Optimization

### Code Splitting
- Page modules loaded dynamically
- Reduces initial bundle size
- Faster page load times

### Lazy Loading
```javascript
// Only load when needed
import('./pages/dashboard.js').then(module => {
    module.initDashboard();
});
```

### Caching
- Browser caches modules automatically
- Version query params force updates
- Static assets have long cache times

## Security Considerations

### API Keys
- Stored in database (local SQLite)
- Environment variable fallback
- Never exposed to frontend directly

### User Input
- Sanitized before display
- AI Guardrails scans all inputs
- No direct eval() or innerHTML with user data

### CORS
- API routes protected
- Same-origin policy enforced

## Testing Strategy

### Manual Testing
- Feature verification on each page
- Cross-browser compatibility
- Module loading confirmation

### Future Automated Testing
- Unit tests for utility functions
- Integration tests for API routes
- E2E tests for user flows

## Migration Guide

### Adding a New Module

1. **Create file** in appropriate directory:
   ```javascript
   // static/js/pages/newpage.js
   export function initNewPage() {
       // Implementation
   }
   ```

2. **Import dependencies**:
   ```javascript
   import { setLoading } from '../shared/utils.js';
   ```

3. **Update `main.js`**:
   ```javascript
   if (document.getElementById("newpage-element")) {
       import('./pages/newpage.js').then(m => m.initNewPage());
   }
   ```

## Future Enhancements

### JavaScript
- [ ] Add TypeScript type definitions
- [ ] Implement service workers

### CSS
- [ ] Create a shared component library
- [ ] Add dark/light theme toggle

### Performance
- [ ] Implement bundle optimization
- [ ] Add compression
- [ ] Optimize image assets
- [ ] Service worker caching

## Resources

- [ES6 Modules (MDN)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules)
- [Dynamic Imports](https://javascript.info/modules-dynamic-imports)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [AI Guardrails API Docs](https://platform.lakera.ai/docs)
