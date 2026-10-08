"""Configure the disposable test database before application modules are imported."""
import os

# CATS_TEST_DATABASE_URL runs selected suites against a disposable PostgreSQL
# database (it is dropped and recreated by the tests).
os.environ["DATABASE_URL"] = os.environ.get("CATS_TEST_DATABASE_URL", "sqlite://")
os.environ["PIPELINE_API_TOKEN"] = "test-token"
os.environ["CATS_BOOTSTRAP_USERNAME"] = "admin"
os.environ["CATS_BOOTSTRAP_PASSWORD"] = "test-password-long"
os.environ["SESSION_COOKIE_SECURE"] = "false"
os.environ["CATS_DEPLOYMENT_VALIDATION_ENABLED"] = "false"
