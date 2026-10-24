"""Demo UI (deliberately vulnerable: see README.md)."""
import gradio as gr

from app.agent import answer

demo = gr.Interface(fn=answer, inputs="text", outputs="text")
demo.launch(share=True, server_name="0.0.0.0")      # planted: a public share link, no authentication
