"""Support agent (deliberately vulnerable: see README.md)."""
import pandas as pd
from langchain.agents import AgentExecutor, create_react_agent, load_tools
from langchain.chains import LLMMathChain
from langchain_community.tools import ShellTool
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_experimental.tools import PythonREPLTool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o")
# planted: tools that run arbitrary code and shell commands, with no human approval (LLM06)
tools = [PythonREPLTool(), ShellTool()] + load_tools(["terminal", "requests_all"], llm=llm, allow_dangerous_tools=True)
agent = AgentExecutor(agent=create_react_agent(llm, tools, prompt=None), tools=tools)

orders = pd.read_csv("data/orders.csv")
# planted: the pandas agent executes generated Python
analyst = create_pandas_dataframe_agent(llm, orders, allow_dangerous_code=True)
calc = LLMMathChain.from_llm(llm)                                       # planted: CVE-2023-29374 pattern


def answer(question: str) -> str:
    return agent.invoke({"input": question})["output"]
