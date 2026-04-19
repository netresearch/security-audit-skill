# Rails Security Patterns

Security patterns, common misconfigurations, and detection regexes for Ruby on Rails applications. Rails provides many security protections by default (CSRF tokens, parameterized queries, automatic HTML escaping), but developers frequently bypass these safeguards through mass assignment misconfiguration, raw HTML output, inline SQL, and improper file handling. Understanding these patterns is essential for auditing Rails applications.

---

## Mass Assignment

### SA-RAILS-01: Strong Parameters Bypass

Rails requires explicit parameter whitelisting via `permit`. However, developers sometimes use `permit!` (which allows all parameters), bypass strong parameters entirely, or permit sensitive fields that should be set server-side.

```ruby
# VULNERABLE: permit! allows ALL parameters including role, is_admin, etc.
class UsersController < ApplicationController
  def create
    @user = User.new(params[:user].permit!)
    @user.save
    redirect_to @user
  end
end

# VULNERABLE: Permitting sensitive fields
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(user_params)
    redirect_to @user
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :role, :is_admin)
    # :role and :is_admin should NEVER be user-controllable
  end
end

# VULNERABLE: Bypassing strong parameters. Modern Rails raises
# ActiveModel::ForbiddenAttributesError if you assign raw
# ActionController::Parameters to a model; the bypass shapes to look
# for in audits are:
#   1. An explicit .permit!  (permit everything)
#   2. to_unsafe_h / to_unsafe_hash (strips the "forbidden" flag)
#   3. .to_h after permit(*Model.attribute_names)  (allowlists every
#      attribute, including role / is_admin)
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.attributes = params[:user].permit!        # permit-everything
    # @user.attributes = params[:user].to_unsafe_h  # equivalent bypass
    @user.save
  end
end
```

```ruby
# SECURE: Only permit safe fields, set sensitive fields server-side
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    @user.role = "user"        # Explicitly set server-side
    @user.is_admin = false     # Explicitly set server-side
    @user.save
    redirect_to @user
  end

  def update
    @user = current_user # Use authenticated user, not params[:id]
    @user.update(user_params)
    redirect_to @user
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :avatar, :bio)
  end
end
```

**Detection regex:** `\.permit!|params\[:[a-z_]+\]\.permit\([^)]*(?:role|admin|superuser|permission)`
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-RAILS-02: html_safe / raw XSS

Rails auto-escapes all output in ERB templates by default. However, calling `html_safe`, `raw()`, or using `<%== %>` explicitly marks content as safe, bypassing escaping. When applied to user-controlled input, this creates XSS vulnerabilities.

```erb
<%# VULNERABLE: html_safe on user input %>
<p>Welcome, <%= @user.name.html_safe %></p>

<%# VULNERABLE: raw() on user input %>
<div><%= raw @comment.body %></div>

<%# VULNERABLE: <%== bypasses escaping %>
<h1><%== @post.title %></h1>

<%# VULNERABLE: html_safe on interpolated user input %>
<div><%= "<b>#{@user.bio}</b>".html_safe %></div>
```

```ruby
# VULNERABLE: html_safe in helper
module ApplicationHelper
  def format_comment(comment)
    comment.body.gsub("\n", "<br>").html_safe
  end
end
```

```erb
<%# SECURE: Default escaping (no html_safe/raw) %>
<p>Welcome, <%= @user.name %></p>
<div><%= @comment.body %></div>

<%# SECURE: Sanitize if HTML is needed %>
<div><%= sanitize @comment.body, tags: %w[b i em strong p br] %></div>

<%# SECURE: Use content_tag for safe HTML generation %>
<%= content_tag :div, @user.bio, class: "bio" %>
```

```ruby
# SECURE: Sanitize in helper
module ApplicationHelper
  def format_comment(comment)
    sanitize(
      simple_format(comment.body),
      tags: %w[p br b i em strong]
    )
  end
end
```

**Detection regex:** `\.html_safe|raw\s*\(|<%==`
**Severity:** error

---

## SQL Injection

### SA-RAILS-03: find_by_sql and String Interpolation in Queries

Rails' ActiveRecord ORM uses parameterized queries by default, but developers can bypass this with `find_by_sql`, string interpolation in `where` clauses, raw SQL fragments, and `order` clauses built from user input.

```ruby
# VULNERABLE: String interpolation in find_by_sql
class User < ApplicationRecord
  def self.search(query)
    find_by_sql("SELECT * FROM users WHERE name LIKE '%#{query}%'")
  end
end

# VULNERABLE: String interpolation in where clause
class PostsController < ApplicationController
  def index
    @posts = Post.where("title LIKE '%#{params[:search]}%'")
  end
end

# VULNERABLE: User-controlled order clause
class PostsController < ApplicationController
  def index
    @posts = Post.order(params[:sort])
    # Attacker sends: sort=(CASE WHEN (SELECT...) THEN name ELSE id END)
  end
end

# VULNERABLE: String interpolation in pluck/select
class ReportsController < ApplicationController
  def show
    columns = params[:columns]
    @data = Report.select(columns).all
  end
end
```

```ruby
# SECURE: Parameterized queries
class User < ApplicationRecord
  def self.search(query)
    where("name LIKE ?", "%#{sanitize_sql_like(query)}%")
  end
end

# SECURE: Using hash conditions
class PostsController < ApplicationController
  def index
    @posts = Post.where(published: true)
    @posts = @posts.where("title LIKE ?", "%#{Post.sanitize_sql_like(params[:search])}%") if params[:search]
  end
end

# SECURE: Allowlist for order clause
ALLOWED_SORT = %w[title created_at updated_at].freeze

class PostsController < ApplicationController
  def index
    sort_col = ALLOWED_SORT.include?(params[:sort]) ? params[:sort] : "created_at"
    direction = params[:dir] == "asc" ? :asc : :desc
    @posts = Post.order(sort_col => direction)
  end
end
```

**Detection regex:** `find_by_sql\s*\(.*#\{|\.where\s*\(.*#\{|\.order\s*\(\s*params`
**Severity:** error

---

## CSRF Protection

### SA-RAILS-04: CSRF Token Configuration

Rails includes CSRF protection by default via `protect_from_forgery`. However, it can be disabled, misconfigured, or bypassed. API-only apps, `skip_before_action`, and wrong `:with` strategies are common pitfalls.

```ruby
# VULNERABLE: CSRF protection disabled
class ApplicationController < ActionController::Base
  skip_before_action :verify_authenticity_token
end

# VULNERABLE: CSRF protection with null_session on non-API controllers
class ApplicationController < ActionController::Base
  protect_from_forgery with: :null_session
  # Attacker can forge requests — session is just silently reset
end

# VULNERABLE: Skipping CSRF for specific actions that modify state
class PaymentsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:webhook, :create]
  # :create should NOT skip CSRF! Only webhooks with signature verification.

  def create
    Payment.create(amount: params[:amount], user: current_user)
  end
end
```

```ruby
# SECURE: Default CSRF with exception strategy
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# SECURE: API controllers use null_session (no cookie-based auth)
class Api::BaseController < ActionController::Base
  protect_from_forgery with: :null_session
  before_action :authenticate_api_token!

  private

  def authenticate_api_token!
    token = request.headers["Authorization"]&.remove("Bearer ")
    @current_user = User.find_by(api_token: token) or head :unauthorized
  end
end

# SECURE: Skip CSRF only for webhook with signature verification
class PaymentsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:webhook]

  def webhook
    verify_webhook_signature!(request)
    # Process webhook...
  end

  def create
    # CSRF token is verified for this action
    Payment.create(amount: params[:amount], user: current_user)
  end
end
```

**Detection regex:** `skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session`
**Severity:** error

---

## Path Traversal

### SA-RAILS-05: send_file / send_data Path Traversal

`send_file` and `send_data` serve files from the server. If the file path includes user input without sanitization, attackers can traverse directories.

```ruby
# VULNERABLE: User-controlled path in send_file
class DownloadsController < ApplicationController
  def show
    # Attacker sends: filename=../../../etc/passwd
    send_file Rails.root.join("uploads", params[:filename])
  end
end

# VULNERABLE: Insufficient sanitization
class DownloadsController < ApplicationController
  def show
    filename = params[:filename].gsub("..", "")
    # Can be bypassed with "....//", URL encoding, etc.
    send_file Rails.root.join("uploads", filename)
  end
end

# VULNERABLE: send_data with user-controlled filename in disposition
class ExportsController < ApplicationController
  def download
    send_data @report.csv_data,
      filename: params[:name], # Header injection via filename
      type: "text/csv"
  end
end
```

```ruby
# SECURE: Validate filename and verify resolved path. Enforce a
# directory boundary when comparing — plain `start_with?(UPLOADS_DIR)`
# would accept "#{UPLOADS_DIR}_private/..." because that's a prefix
# of the allowed root. Append File::SEPARATOR before comparing.
class DownloadsController < ApplicationController
  UPLOADS_DIR = Rails.root.join("uploads").to_s
  UPLOADS_ROOT = UPLOADS_DIR + File::SEPARATOR

  def show
    basename = File.basename(params[:filename]) # Strip directory components
    full_path = File.realpath(File.join(UPLOADS_DIR, basename))

    unless full_path == UPLOADS_DIR || full_path.start_with?(UPLOADS_ROOT)
      head :not_found
      return
    end

    send_file full_path
  end
end

# SECURE: Use database lookup instead of filesystem path
class DownloadsController < ApplicationController
  def show
    attachment = current_user.attachments.find(params[:id])
    send_file attachment.file_path, filename: attachment.original_filename
  end
end
```

**Detection regex:** `send_file\s*.*params\[|send_data\s*.*filename:\s*params\[`
**Severity:** error

---

## Template Injection

### SA-RAILS-06: render inline: Template Injection

`render inline:` compiles and executes ERB templates at runtime. If the template string includes user input, attackers can execute arbitrary Ruby code via ERB tags.

```ruby
# VULNERABLE: User input in inline template
class PagesController < ApplicationController
  def preview
    template = params[:template]
    # Attacker sends: template=<%= system('id') %>
    render inline: template
  end
end

# VULNERABLE: String interpolation in inline template
class NotificationsController < ApplicationController
  def show
    message = params[:message]
    render inline: "<p>Message: #{message}</p>"
  end
end

# VULNERABLE: User input in render with layout
class PagesController < ApplicationController
  def show
    render inline: "Hello", layout: params[:layout]
  end
end
```

```ruby
# SECURE: Use templates with variables, never inline with user input
class PagesController < ApplicationController
  def preview
    @message = params[:message]
    render template: "pages/preview" # Uses app/views/pages/preview.html.erb
  end
end

# SECURE: Allowlist for layout
ALLOWED_LAYOUTS = %w[default minimal print].freeze

class PagesController < ApplicationController
  def show
    layout = ALLOWED_LAYOUTS.include?(params[:layout]) ? params[:layout] : "default"
    render template: "pages/show", layout: layout
  end
end
```

**Detection regex:** `render\s+inline:\s*.*params\[|render\s+inline:\s*.*#\{`
**Severity:** error

---

## File Upload Validation

### SA-RAILS-07: Active Storage File Validation

Active Storage does not validate file types or sizes by default. Without validation, attackers can upload executable files, oversized files (DoS), or files with mismatched content types.

```ruby
# VULNERABLE: No file validation
class User < ApplicationRecord
  has_one_attached :avatar
  # No content_type or size validation!
end

# VULNERABLE: Client-side only validation (easily bypassed)
class UsersController < ApplicationController
  def update
    # Client-side accept attribute is NOT security
    @user.avatar.attach(params[:avatar])
  end
end
```

```ruby
# SECURE: Server-side validation with Active Storage validations
class User < ApplicationRecord
  has_one_attached :avatar

  validates :avatar,
    content_type: %w[image/png image/jpeg image/gif image/webp],
    size: { less_than: 5.megabytes }
end

# SECURE: Manual validation in controller
class UsersController < ApplicationController
  ALLOWED_TYPES = %w[image/png image/jpeg image/gif].freeze
  MAX_SIZE = 5.megabytes

  def update
    file = params[:avatar]
    unless file.content_type.in?(ALLOWED_TYPES) && file.size <= MAX_SIZE
      flash[:error] = "Invalid file"
      redirect_to edit_user_path and return
    end

    @user.avatar.attach(file)
    redirect_to @user
  end
end
```

**Detection regex:** `has_one_attached\s+:\w+(?![\s\S]*?validates\s+:\w+.*content_type)|has_many_attached\s+:\w+(?![\s\S]*?validates\s+:\w+.*content_type)`
**Severity:** warning

---

## Action Cable Authentication

### SA-RAILS-08: Action Cable Auth

Action Cable (WebSocket) connections require explicit authentication. Without it, any client can subscribe to channels and receive real-time data.

```ruby
# VULNERABLE: No authentication in connection
module ApplicationCable
  class Connection < ActionCable::Connection::Base
    # No identified_by — anyone can connect
  end
end

# VULNERABLE: Channel without authorization
class AdminChannel < ApplicationCable::Channel
  def subscribed
    stream_from "admin_notifications"
    # Any connected user (or anonymous user) receives admin data!
  end
end
```

```ruby
# SECURE: Authenticate connection via cookies/session
module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :current_user

    def connect
      self.current_user = find_verified_user
    end

    private

    def find_verified_user
      user = User.find_by(id: cookies.encrypted[:user_id])
      user || reject_unauthorized_connection
    end
  end
end

# SECURE: Authorize channel subscriptions
class AdminChannel < ApplicationCable::Channel
  def subscribed
    reject unless current_user.admin?
    stream_from "admin_notifications"
  end
end
```

**Detection regex:** `class\s+\w+Channel\s*<\s*ApplicationCable::Channel[\s\S]*?def\s+subscribed(?![\s\S]*?reject\b)`
**Severity:** error

---

## protect_from_forgery Ordering

### SA-RAILS-09: protect_from_forgery Ordering

When `protect_from_forgery with: :exception` is placed after `before_action` callbacks that modify state, a CSRF attack can trigger those callbacks before the token is verified.

```ruby
# VULNERABLE: State-changing callback runs before CSRF check
class ApplicationController < ActionController::Base
  before_action :set_locale_from_param  # Runs first
  before_action :track_visit            # Runs second — writes to DB!
  protect_from_forgery with: :exception # Runs third — too late
end
```

```ruby
# SECURE: protect_from_forgery before state-changing callbacks
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception  # Runs first
  before_action :set_locale_from_param
  before_action :track_visit
end
```

**Detection regex:** `before_action\s+:\w+[\s\S]*?protect_from_forgery`
**Severity:** warning

---

## Unsafe Deserialization

### SA-RAILS-10: Marshal.load / YAML.load with User Input

`Marshal.load` and `YAML.load` can execute arbitrary Ruby code when deserializing untrusted data. Rails historically used YAML for session serialization, making this a well-known attack vector.

```ruby
# VULNERABLE: Marshal.load on user input
class ImportController < ApplicationController
  def create
    data = Marshal.load(Base64.decode64(params[:data]))
    # Arbitrary code execution via crafted Marshal payload
  end
end

# VULNERABLE: YAML.load on user input
class ConfigController < ApplicationController
  def update
    config = YAML.load(params[:yaml_content])
    # Arbitrary code execution via YAML deserialization gadgets
  end
end
```

```ruby
# SECURE: Use JSON or YAML.safe_load
class ImportController < ApplicationController
  def create
    data = JSON.parse(params[:data])
    process_import(data)
  end
end

# SECURE: YAML.safe_load with permitted classes
class ConfigController < ApplicationController
  def update
    config = YAML.safe_load(
      params[:yaml_content],
      permitted_classes: [Symbol, Date, Time]
    )
    apply_config(config)
  end
end
```

**Detection regex:** `Marshal\.load\s*\(|YAML\.load\s*\([^)]*params`
**Severity:** error

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-RAILS-01 Mass assignment | Critical | Immediate | Low |
| SA-RAILS-02 html_safe/raw XSS | Critical | Immediate | Low |
| SA-RAILS-03 SQL injection | Critical | Immediate | Medium |
| SA-RAILS-04 CSRF misconfiguration | High | Immediate | Low |
| SA-RAILS-05 Path traversal | Critical | Immediate | Medium |
| SA-RAILS-06 Template injection | Critical | Immediate | Low |
| SA-RAILS-07 Active Storage validation | Medium | 1 week | Low |
| SA-RAILS-08 Action Cable auth | High | 1 week | Medium |
| SA-RAILS-09 protect_from_forgery ordering | Medium | 1 week | Low |
| SA-RAILS-10 Unsafe deserialization | Critical | Immediate | Low |

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `api-security.md` -- API-level security patterns
- Rails Security Guide: https://guides.rubyonrails.org/security.html

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 framework expansion |
