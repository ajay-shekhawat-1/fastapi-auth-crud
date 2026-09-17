import { useEffect, useMemo, useState } from "react";

const API_URL = import.meta.env.VITE_API_BASE_URL;

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [userName, setUserName] = useState(
    localStorage.getItem("user_name") || ""
  );
  const [role, setRole] = useState(localStorage.getItem("role") || "");

  const [page, setPage] = useState("dashboard");

  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [showUserModal, setShowUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);

  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    mobile: "",
    address: "",
  });

  const isAdmin = role === "Admin";
  const isSuperAdmin = role === "Super Admin";
  const canManageUsers = isAdmin || isSuperAdmin;

  useEffect(() => {
    if (token) {
      fetchUsers();
      fetchRoles();
    }
  }, [token]);

  const authHeaders = {
    Authorization: `Bearer ${token}`,
  };

  async function fetchUsers() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_URL}/users`, {
        headers: authHeaders,
      });

      if (!response.ok) {
        throw new Error("Unable to load users");
      }

      const data = await response.json();
      setUsers(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function fetchRoles() {
    try {
      const response = await fetch(`${API_URL}/roles`, {
        headers: authHeaders,
      });

      if (response.ok) {
        const data = await response.json();
        setRoles(data);
      }
    } catch (err) {
      console.error(err);
    }
  }

  function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user_name");
    localStorage.removeItem("role");
    localStorage.removeItem("user_id");

    setToken(null);
    setUserName("");
    setRole("");
  }

  function openAddModal() {
    setEditingUser(null);

    setForm({
      name: "",
      email: "",
      password: "",
      mobile: "",
      address: "",
    });

    setShowUserModal(true);
  }

  function openEditModal(user) {
    setEditingUser(user);

    setForm({
      name: user.name || "",
      email: user.email || "",
      password: "",
      mobile: user.mobile || "",
      address: user.address || "",
    });

    setShowUserModal(true);
  }

  function closeModal() {
    setShowUserModal(false);
    setEditingUser(null);
  }

  function handleChange(event) {
    const { name, value } = event.target;

    setForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  }

  async function saveUser(event) {
    event.preventDefault();

    try {
      setLoading(true);
      setError("");

      const url = editingUser
        ? `${API_URL}/users/${editingUser.id}`
        : `${API_URL}/users`;

      const method = editingUser ? "PUT" : "POST";

      const response = await fetch(url, {
        method,
        headers: {
          ...authHeaders,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Operation failed");
      }

      closeModal();
      await fetchUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function deleteUser(userId) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this user?"
    );

    if (!confirmed) {
      return;
    }

    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_URL}/users/${userId}`, {
        method: "DELETE",
        headers: authHeaders,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to delete user");
      }

      await fetchUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function changeRole(userId, roleId) {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_URL}/users/${userId}/role`, {
        method: "PUT",
        headers: {
          ...authHeaders,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          role_id: Number(roleId),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to change role");
      }

      await fetchUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const totalUsers = users.length;

  const totalAdmins = users.filter(
    (user) => user.role === "Admin"
  ).length;

  const totalNormalUsers = users.filter(
    (user) => user.role === "User"
  ).length;

  const totalSuperAdmins = users.filter(
    (user) => user.role === "Super Admin"
  ).length;

  const stats = useMemo(
    () => [
      {
        label: "Total users",
        value: totalUsers,
        description: "Registered accounts",
        icon: "◉",
      },
      {
        label: "Administrators",
        value: totalAdmins,
        description: "Admin accounts",
        icon: "◆",
      },
      {
        label: "Standard users",
        value: totalNormalUsers,
        description: "User accounts",
        icon: "●",
      },
      {
        label: "Super admins",
        value: totalSuperAdmins,
        description: "Full access",
        icon: "★",
      },
    ],
    [totalUsers, totalAdmins, totalNormalUsers, totalSuperAdmins]
  );

  if (!token) {
    return (
      <AuthScreen
        API_URL={API_URL}
        setToken={setToken}
        setUserName={setUserName}
        setRole={setRole}
      />
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">A</div>

          <div>
            <div className="brand-name">AccessHub</div>
            <div className="brand-subtitle">User management</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button
            className={`nav-item ${page === "dashboard" ? "active" : ""}`}
            onClick={() => setPage("dashboard")}
          >
            <span>⌂</span>
            Dashboard
          </button>

          <button
            className={`nav-item ${page === "users" ? "active" : ""}`}
            onClick={() => setPage("users")}
          >
            <span>♙</span>
            Users
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="access-box">
            <span className="access-dot"></span>

            <div>
              <strong>{role}</strong>
              <small>Current access</small>
            </div>
          </div>

          <button className="logout-button" onClick={logout}>
            <span>↪</span>
            Sign out
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="breadcrumb">Workspace / {page}</div>
            <h1>
              {page === "dashboard" ? "Dashboard" : "User management"}
            </h1>
          </div>

          <div className="profile">
            <div className="profile-text">
              <strong>{userName}</strong>
              <span>{role}</span>
            </div>

            <div className="avatar">
              {userName.charAt(0).toUpperCase()}
            </div>
          </div>
        </header>

        {error && (
          <div className="alert">
            <span>!</span>
            {error}
            <button onClick={() => setError("")}>×</button>
          </div>
        )}

        {page === "dashboard" && (
          <>
            <section className="welcome-section">
              <div>
                <span className="eyebrow">OVERVIEW</span>

                <h2>Good to see you, {userName.split(" ")[0]}.</h2>

                <p>
                  Manage accounts, access levels and user information from one
                  place.
                </p>
              </div>

              {canManageUsers && (
                <button className="primary-button" onClick={openAddModal}>
                  <span>+</span>
                  Add user
                </button>
              )}
            </section>

            <section className="stats-grid">
              {stats.map((stat) => (
                <div className="stat-card" key={stat.label}>
                  <div className="stat-top">
                    <span className="stat-label">{stat.label}</span>
                    <span className="stat-icon">{stat.icon}</span>
                  </div>

                  <strong>{stat.value}</strong>
                  <span className="stat-description">
                    {stat.description}
                  </span>
                </div>
              ))}
            </section>

            <section className="content-card">
              <div className="card-heading">
                <div>
                  <span className="eyebrow">RECENT ACCOUNTS</span>
                  <h3>Users</h3>
                </div>

                <button
                  className="text-button"
                  onClick={() => setPage("users")}
                >
                  View all →
                </button>
              </div>

              <UsersTable
                users={users.slice(0, 5)}
                loading={loading}
                canManageUsers={canManageUsers}
                isSuperAdmin={isSuperAdmin}
                roles={roles}
                onEdit={openEditModal}
                onDelete={deleteUser}
                onChangeRole={changeRole}
              />
            </section>
          </>
        )}

        {page === "users" && (
          <section className="content-card users-page-card">
            <div className="card-heading">
              <div>
                <span className="eyebrow">DIRECTORY</span>
                <h3>All users</h3>
                <p className="heading-description">
                  View and manage registered accounts.
                </p>
              </div>

              {canManageUsers && (
                <button className="primary-button" onClick={openAddModal}>
                  <span>+</span>
                  Add user
                </button>
              )}
            </div>

            <UsersTable
              users={users}
              loading={loading}
              canManageUsers={canManageUsers}
              isSuperAdmin={isSuperAdmin}
              roles={roles}
              onEdit={openEditModal}
              onDelete={deleteUser}
              onChangeRole={changeRole}
            />
          </section>
        )}
      </main>

      {showUserModal && (
        <UserModal
          form={form}
          editingUser={editingUser}
          loading={loading}
          onChange={handleChange}
          onSubmit={saveUser}
          onClose={closeModal}
        />
      )}
    </div>
  );
}

function UsersTable({
  users,
  loading,
  canManageUsers,
  isSuperAdmin,
  roles,
  onEdit,
  onDelete,
  onChangeRole,
}) {
  if (loading && users.length === 0) {
    return <div className="empty-state">Loading users...</div>;
  }

  if (users.length === 0) {
    return <div className="empty-state">No users found.</div>;
  }

  return (
    <div className="table-wrapper">
      <table className="users-table">
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Mobile</th>
            <th>Role</th>
            {canManageUsers && <th className="actions-column">Actions</th>}
          </tr>
        </thead>

        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>
                <div className="user-cell">
                  <div className="user-avatar">
                    {user.name?.charAt(0).toUpperCase()}
                  </div>

                  <div>
                    <strong>{user.name}</strong>
                    <small>ID #{user.id}</small>
                  </div>
                </div>
              </td>

              <td>{user.email}</td>

              <td>{user.mobile || "—"}</td>

              <td>
                {isSuperAdmin ? (
                  <select
                    className="role-select"
                    value={
                      roles.find((item) => item.name === user.role)?.id || ""
                    }
                    onChange={(event) =>
                      onChangeRole(user.id, event.target.value)
                    }
                  >
                    {roles.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <RoleBadge role={user.role} />
                )}
              </td>

              {canManageUsers && (
                <td>
                  <div className="action-buttons">
                    <button
                      className="icon-button edit"
                      onClick={() => onEdit(user)}
                      title="Edit user"
                    >
                      ✎
                    </button>

                    <button
                      className="icon-button delete"
                      onClick={() => onDelete(user.id)}
                      title="Delete user"
                    >
                      ×
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RoleBadge({ role }) {
  const roleClass =
    role === "Super Admin"
      ? "super-admin"
      : role === "Admin"
      ? "admin"
      : "user";

  return <span className={`role-badge ${roleClass}`}>{role}</span>;
}

function UserModal({
  form,
  editingUser,
  loading,
  onChange,
  onSubmit,
  onClose,
}) {
  return (
    <div className="modal-overlay" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">ACCOUNT</span>
            <h3>{editingUser ? "Edit user" : "Create user"}</h3>
          </div>

          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <form onSubmit={onSubmit}>
          <div className="form-grid">
            <div className="form-field">
              <label>Name</label>
              <input
                name="name"
                value={form.name}
                onChange={onChange}
                placeholder="Enter full name"
                required
              />
            </div>

            <div className="form-field">
              <label>Email</label>
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={onChange}
                placeholder="name@example.com"
                required
              />
            </div>

            <div className="form-field">
              <label>
                Password
                {editingUser && <span> — leave blank to keep current</span>}
              </label>

              <input
                type="password"
                name="password"
                value={form.password}
                onChange={onChange}
                placeholder={
                  editingUser ? "Leave blank if unchanged" : "Enter password"
                }
                required={!editingUser}
              />
            </div>

            <div className="form-field">
              <label>Mobile</label>
              <input
                name="mobile"
                value={form.mobile}
                onChange={onChange}
                placeholder="Enter mobile number"
              />
            </div>

            <div className="form-field full-width">
              <label>Address</label>
              <input
                name="address"
                value={form.address}
                onChange={onChange}
                placeholder="Enter address"
              />
            </div>
          </div>

          <div className="modal-footer">
            <button
              type="button"
              className="secondary-button"
              onClick={onClose}
            >
              Cancel
            </button>

            <button type="submit" className="primary-button" disabled={loading}>
              {loading
                ? "Saving..."
                : editingUser
                ? "Save changes"
                : "Create user"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function AuthScreen({ API_URL, setToken, setUserName, setRole }) {
  const [mode, setMode] = useState("login");
  const [selectedRole, setSelectedRole] = useState("User");

  const [form, setForm] = useState({
    email: "",
    password: "",
    name: "",
    mobile: "",
    address: "",
  });

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function handleChange(event) {
    const { name, value } = event.target;

    setForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  }

  async function submit(event) {
    event.preventDefault();

    try {
      setLoading(true);
      setError("");

      if (mode === "login") {
        const body = new URLSearchParams();

        body.append("username", form.email);
        body.append("password", form.password);

        const response = await fetch(`${API_URL}/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body,
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "Invalid email or password");
        }

        localStorage.setItem("token", data.access_token);
        localStorage.setItem("user_name", data.user_name);
        localStorage.setItem("role", data.role);
        localStorage.setItem("user_id", data.user_id);

        setToken(data.access_token);
        setUserName(data.user_name);
        setRole(data.role);
      } else {
        const response = await fetch(`${API_URL}/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: form.name,
            email: form.email,
            password: form.password,
            mobile: form.mobile || null,
            address: form.address || null,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "Registration failed");
        }

        setMode("login");

        setForm({
          email: form.email,
          password: "",
          name: "",
          mobile: "",
          address: "",
        });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const fillSuperAdminCredentials = () => {
    setForm((previous) => ({
      ...previous,
      email: "superadmin@gmail.com",
      password: "Superadmin@123",
    }));
  };

  return (
    <div className="auth-page">
      <div className="auth-panel">
        <div className="auth-brand">
          <div className="brand-mark">A</div>
          <span>AccessHub</span>
        </div>

        <div className="auth-content">
          <span className="eyebrow">
            {mode === "login" ? "WELCOME BACK" : "GET STARTED"}
          </span>

          <h1>{mode === "login" ? "Sign in to your workspace" : "Create your account"}</h1>

          <p>
            {mode === "login"
              ? "Enter your credentials to continue."
              : "Create a standard user account to get started."}
          </p>

          {error && (
            <div className="auth-error">
              <span>!</span>
              {error}
            </div>
          )}

          <form onSubmit={submit} className="auth-form">
            {mode === "register" && (
              <>
                <div className="form-field">
                  <label>Name</label>
                  <input
                    name="name"
                    value={form.name}
                    onChange={handleChange}
                    placeholder="Your full name"
                    required
                  />
                </div>

                <div className="form-field">
                  <label>Mobile</label>
                  <input
                    name="mobile"
                    value={form.mobile}
                    onChange={handleChange}
                    placeholder="Mobile number"
                  />
                </div>
              </>
            )}

            <div className="form-field">
              <label>Email</label>
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                placeholder="you@example.com"
                required
              />
            </div>

            <div className="form-field">
              <label>Password</label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Enter password"
                required
              />
            </div>

            {mode === "register" && (
              <div className="form-field">
                <label>Address</label>
                <input
                  name="address"
                  value={form.address}
                  onChange={handleChange}
                  placeholder="Your address"
                />
              </div>
            )}

            {mode === "login" && (
              <>
                <div className="role-buttons">
                  <button
                    type="button"
                    className={selectedRole === "User" ? "active" : ""}
                    onClick={() => setSelectedRole("User")}
                  >
                    User
                  </button>

                  <button
                    type="button"
                    className={selectedRole === "Admin" ? "active" : ""}
                    onClick={() => setSelectedRole("Admin")}
                  >
                    Admin
                  </button>

                  <button
                    type="button"
                    className={selectedRole === "Super Admin" ? "active" : ""}
                    onClick={() => setSelectedRole("Super Admin")}
                  >
                    Super Admin
                  </button>
                </div>

                {selectedRole === "Super Admin" && (
                  <div className="demo-access-card">
                    <div className="demo-access-header">
                      <div className="demo-access-icon">🛡</div>

                      <div>
                        <h3>Super Admin Demo Access</h3>
                        <p>Use the demo account to explore Super Admin features.</p>
                      </div>
                    </div>

                    <div className="demo-credentials">
                      <div className="credential-row">
                        <span>Email</span>
                        <strong>superadmin@gmail.com</strong>
                      </div>

                      <div className="credential-row">
                        <span>Password</span>
                        <strong>Superadmin@123</strong>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="demo-credentials-button"
                      onClick={fillSuperAdminCredentials}
                    >
                      Use Demo Credentials
                    </button>
                  </div>
                )}
              </>
            )}

            <button className="auth-submit" disabled={loading}>
              {loading
                ? "Please wait..."
                : mode === "login"
                ? "Sign in"
                : "Create account"}
            </button>
          </form>

          <div className="auth-switch">
            {mode === "login" ? (
              <>
                Don't have an account?
                <button onClick={() => setMode("register")}>
                  Create account
                </button>
              </>
            ) : (
              <>
                Already have an account?
                <button onClick={() => setMode("login")}>
                  Sign in
                </button>
              </>
            )}
          </div>
        </div>

        <div className="auth-footer">
          Secure role-based access management
        </div>
      </div>

      <div className="auth-visual">
        <div className="visual-content">
          <span className="visual-label">ACCESS MANAGEMENT</span>

          <h2>
            One workspace.
            <br />
            Clear permissions.
          </h2>

          <p>
            Manage users and access levels with a simple role-based
            administration system.
          </p>

          <div className="visual-line"></div>

          <div className="visual-meta">
            <span>USER</span>
            <span>ADMIN</span>
            <span>SUPER ADMIN</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;