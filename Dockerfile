FROM python:3.11-slim

# Hugging Face Spaces requires the container to run as a non-root user with UID 1000.
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"
WORKDIR /home/user/app

# Install Python deps as the non-root user to avoid permission issues.
COPY --chown=user requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Copy the rest of the repo (streamlit_app.py, evals/, threat model, architecture, etc).
COPY --chown=user . .

# Hugging Face Spaces serves on port 7860 by convention.
EXPOSE 7860

CMD ["streamlit", "run", "streamlit_app.py", \
     "--server.port=7860", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
