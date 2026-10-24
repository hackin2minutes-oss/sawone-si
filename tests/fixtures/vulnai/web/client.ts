// Browser chat client (deliberately vulnerable: see README.md)
import OpenAI from "openai";

// planted: the provider key ships to every visitor's browser
export const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY, dangerouslyAllowBrowser: true });

export async function ask(question: string): Promise<string> {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: question }],
  });
  const text = completion.choices[0].message.content ?? "";
  if (text.startsWith("CALC:")) {
    return String(eval(text.slice(5)));          // planted: model output evaluated
  }
  return text;
}
