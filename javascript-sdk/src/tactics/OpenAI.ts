import { RebuffError, TacticName } from "../interface.js";
import { OpenAIApi } from "openai";
import { renderPromptForPiDetection } from "../lib/prompts.js";
import { parseModelScore } from "../lib/score.js";
import Tactic, { TacticExecution } from "./Tactic.js";

export default class OpenAI implements Tactic {
  name = TacticName.LanguageModel;
  private openai: OpenAIApi;
  private model: string;
  public defaultThreshold: number;

  constructor(threshold: number, model: string, openai: OpenAIApi) {
    this.defaultThreshold = threshold;
    this.model = model;
    this.openai = openai;
  }

  async execute(input: string): Promise<TacticExecution> {
    try {
      const completion = await this.openai.createChatCompletion({
        model: this.model,
        messages: [{ role: "user", content: renderPromptForPiDetection(input) }],
      });
  
      if (completion.data.choices.length === 0) {
        throw new Error("completion.data.choices.length === 0");
      }
      if (completion.data.choices[0].message === undefined) {
        throw new Error("completion.data.choices[0].message is undefined");
      }

      const score = parseModelScore(completion.data.choices[0].message.content);
      return { score };
    } catch (error) {
      if (error instanceof RebuffError) {
        // Already a precise, fail-closed error (bad or unparseable score). Do not
        // flatten it into a generic message -- callers need to know the check failed.
        throw error;
      }
      console.error("Error in callOpenAiToDetectPI:", error);
      throw new RebuffError("Error in getting score for large language model");
    }
  }
}
