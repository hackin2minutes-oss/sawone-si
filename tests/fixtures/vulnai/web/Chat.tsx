// Chat bubble (deliberately vulnerable: see README.md)
import { useState } from "react";
import { ask } from "./client";

export function Chat() {
  const [answer, setAnswer] = useState("");
  async function send(q: string) {
    const completion = await ask(q);
    setAnswer(completion);
  }
  // planted: model output rendered as HTML (stored XSS, markdown image exfiltration)
  return <div className="bubble" dangerouslySetInnerHTML={{ __html: answer }} onClick={() => send("hi")} />;
}
