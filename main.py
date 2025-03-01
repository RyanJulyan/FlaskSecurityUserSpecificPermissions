import os

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
    UserMixin,
    RoleMixin,
    auth_required,
    permissions_required,
)
from flask_security.models import fsqla_v3 as fsqla

# --- Initialize Flask app ---
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SECURITY_PASSWORD_SALT"] = "somesalt"
app.config["SECURITY_REGISTERABLE"] = True
app.config["SECURITY_TRACKABLE"] = True
app.config["SECURITY_PASSWORD_HASH"] = "argon2"

# Mail Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER',
                                                   app.config['MAIL_USERNAME'])

# Initialize extensions
db = SQLAlchemy(app)

# Initialize Flask-Mail
mail = Mail(app)

# --- Association tables ---

# Define models and
# Initialize FsModels with our SQLAlchemy instance
fsqla.FsModels.set_db_info(db)

# Roles ↔ Permissions (many-to-many)
roles_permissions = db.Table(
    "roles_permissions",
    db.Column("role_id",
              db.Integer,
              db.ForeignKey("role.id"),
              primary_key=True),
    db.Column("permission_id",
              db.Integer,
              db.ForeignKey("permission.id"),
              primary_key=True),
)

# Users ↔ Permissions (many-to-many) for direct user permissions
users_permissions = db.Table(
    "users_permissions",
    db.Column("user_id",
              db.Integer,
              db.ForeignKey("user.id"),
              primary_key=True),
    db.Column("permission_id",
              db.Integer,
              db.ForeignKey("permission.id"),
              primary_key=True),
)

# --- Models ---


class Permission(db.Model):
    """A separate table to store permission names."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f"{self.name}"

    def __str__(self):
        return f"{self.name}"


class Role(db.Model, fsqla.FsRoleMixin):
    """Flask-Security Role model, extended to have many Permissions."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

    # Many-to-many reference to Permission
    permissions = db.relationship(
        "Permission",
        secondary=roles_permissions,
        backref=db.backref("roles", lazy="dynamic"),
    )

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model, fsqla.FsUserMixin):
    """Flask-Security User model, extended to have direct Permissions."""

    # Many-to-many reference to Permission (for direct user permissions)
    permissions = db.relationship(
        "Permission",
        secondary=users_permissions,
        backref=db.backref("users", lazy="dynamic"),
    )

    def has_permissions(self, permission_names):
        """
        Override the check so `@permissions_required(names)` verifies:
            1) Direct user permissions
            2) Permissions via any role
        
        This matches Flask-Security's expected method name and signature.
        """
        # Check if permission_names is a string or list
        if isinstance(permission_names, str):
            permission_names = [permission_names]

        # Ensure all required permissions are present
        for permission_name in permission_names:
            has_this_permission = False

            # Check direct user permissions
            for p in self.permissions:
                if p.name == permission_name:
                    has_this_permission = True
                    break

            # If not found in direct permissions, check role permissions
            if not has_this_permission:
                for role in self.roles:
                    for rp in role.permissions:
                        if rp.name == permission_name:
                            has_this_permission = True
                            break
                    if has_this_permission:
                        break

            # If this permission is not found anywhere, return False
            if not has_this_permission:
                return False

        # All permissions were found
        return True

    def __repr__(self):
        return f"<User {self.email}>"


class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
    pass


# --- Setup Flask-Security ---
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, mail_util=mail)


# --- DB creation and seeding (NO before_first_request) ---
def create_and_seed_db():
    print()
    print("*" * 20)
    print("Creating database tables...")
    print("*" * 20)
    print()
    db.create_all()

    # Verify if hashing is properly configured
    print("Using password hash:", app.config["SECURITY_PASSWORD_HASH"])

    #
    # 1) Create permissions if not present
    #
    def get_or_create_permission(name: str) -> Permission:
        perm = Permission.query.filter_by(name=name).first()
        if not perm:
            perm = Permission(name=name)
            db.session.add(perm)
            db.session.commit()  # commit so 'perm.id' is available
        return perm

    admin_perm = get_or_create_permission("admin")
    read_perm = get_or_create_permission("read")
    write_perm = get_or_create_permission("write")

    #
    # 2) Create roles if not present
    #
    admin_role = user_datastore.find_role("admin")
    if not admin_role:
        admin_role = user_datastore.create_role(name="admin")
        db.session.add(admin_role)

    user_role = user_datastore.find_role("user")
    if not user_role:
        user_role = user_datastore.create_role(name="user")
        db.session.add(user_role)

    db.session.commit()

    #
    # 3) Assign permissions to roles if not already assigned
    #
    def add_perm_to_role(role: Role, perm: Permission):
        if perm not in role.permissions:
            role.permissions.append(perm)

    # Admin role: admin, read, write
    add_perm_to_role(admin_role, admin_perm)
    add_perm_to_role(admin_role, read_perm)
    add_perm_to_role(admin_role, write_perm)

    # User role: read
    add_perm_to_role(user_role, read_perm)

    db.session.commit()

    #
    # 4) Create users if not present
    #
    admin_user = user_datastore.find_user(email="admin@example.com")
    if not admin_user:
        admin_user = user_datastore.create_user(
            email="admin@example.com",
            password="password",
            roles=[admin_role],  # has the "admin" role
        )
        db.session.add(admin_user)
    else:
        # Update password for existing admin user
        admin_user.password = "password"

    direct_user = user_datastore.find_user(email="direct@example.com")
    if not direct_user:
        direct_user = user_datastore.create_user(
            email="direct@example.com",
            password="password",
            roles=[user_role],  # has "read" from the "user" role
        )
        db.session.add(direct_user)
    else:
        # Update password for existing direct user
        direct_user.password = "password"

    db.session.commit()

    #
    # 5) If the "direct" user exists, ensure they have the "admin" permission directly
    #
    if admin_perm not in direct_user.permissions:
        direct_user.permissions.append(admin_perm)
        db.session.commit()


# --- Routes ---

# Initialize the database during startup instead of on first request
with app.app_context():
    create_and_seed_db()


@app.route("/admin")
@auth_required("session")
def admin_dashboard():
    # Get the current user for debugging
    from flask_security import current_user
    from flask import request

    # Print request information
    print(f"Request headers: {dict(request.headers)}")

    # Check permission directly
    print(f"User: {current_user.email}")
    print(
        f"User has admin permission? {current_user.has_permissions('admin')}")

    # Examine roles and permissions in detail
    roles = [role.name for role in current_user.roles]
    print(f"User roles: {roles}")

    all_perms = []
    for role in current_user.roles:
        role_perms = [p.name for p in role.permissions]
        print(f"Role {role.name} permissions: {role_perms}")
        all_perms.extend(role_perms)

    print(f"All permissions via roles: {all_perms}")

    # If permission check passes, return success
    if current_user.has_permissions('admin'):
        return jsonify({
            "message": "You have ADMIN access!",
            "debug_info": {
                "user": current_user.email,
                "roles": roles,
                "permissions": all_perms
            }
        })
    else:
        # Return detailed error response
        return jsonify({
            "error": "Forbidden",
            "debug_info": {
                "user": current_user.email,
                "roles": roles,
                "permissions": all_perms,
                "has_admin_permission": current_user.has_permissions('admin')
            }
        }), 403


@app.route("/read")
@auth_required("session")
@permissions_required("read")
def read_something():
    return jsonify({"message": "You have READ access!"})


@app.route("/write")
@auth_required("session")
@permissions_required("write")
def write_something():
    return jsonify({"message": "You have WRITE access!"})


# --- Start the app: Create/Seed DB once, then run ---
if __name__ == "__main__":

    app.run(debug=True)
