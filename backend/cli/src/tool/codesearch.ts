import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./codesearch.txt"

const API_CONFIG = {
  BASE_URL: "https://mcp.exa.ai",
  ENDPOINTS: {
    CONTEXT: "/mcp",
  },
} as const

// web_search_exa is a general web search; the objective is what ranks
// documentation and code above everything else.
const OBJECTIVE =
  "Programming reference lookup. Rank official documentation, API references, source repositories and worked code examples first; exclude marketing pages, news and unrelated results. Pull concrete code snippets, function signatures and configuration options."

interface McpCodeRequest {
  jsonrpc: string
  id: number
  method: string
  params: {
    name: string
    arguments: {
      query: string
      objective: string
      numResults: number
    }
  }
}

interface McpCodeResponse {
  jsonrpc: string
  error?: {
    code: number
    message: string
  }
  result?: {
    isError?: boolean
    content?: Array<{
      type: string
      text: string
    }>
  }
}

export const CodeSearchTool = Tool.define("codesearch", {
  description: DESCRIPTION,
  parameters: z.object({
    query: z
      .string()
      .describe(
        "Describe the page you want, naming the library, API or language. For example, 'pandas DataFrame filtering rows by condition with examples', 'Express.js error-handling middleware', 'Next.js partial prerendering configuration'",
      ),
    numResults: z
      .number()
      .int()
      .min(1)
      .max(10)
      .default(5)
      .describe(
        "Number of pages to return (1-10). Default is 5. Each page contributes its title, URL and highlighted excerpts, so fewer pages keep the result focused.",
      ),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "codesearch",
      patterns: [params.query],
      always: ["*"],
      metadata: {
        query: params.query,
        numResults: params.numResults,
      },
    })

    const codeRequest: McpCodeRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "web_search_exa",
        arguments: {
          query: params.query,
          objective: OBJECTIVE,
          numResults: params.numResults,
        },
      },
    }

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 30000)

    try {
      const headers: Record<string, string> = {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      }

      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CONTEXT}`, {
        method: "POST",
        headers,
        body: JSON.stringify(codeRequest),
        signal: AbortSignal.any([controller.signal, ctx.abort]),
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Code search error (${response.status}): ${errorText}`)
      }

      const responseText = await response.text()

      // Parse SSE response
      const lines = responseText.split("\n")
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data: McpCodeResponse = JSON.parse(line.substring(6))
          if (data.error) throw new Error(`Code search error (${data.error.code}): ${data.error.message}`)
          const text = (data.result?.content ?? [])
            .filter((part) => part.type === "text")
            .map((part) => part.text)
            .join("\n\n")
          if (data.result?.isError)
            throw new Error(`Code search error: ${text || "the search tool reported a failure"}`)
          if (text) {
            return {
              output: text,
              title: `Code search: ${params.query}`,
              metadata: {},
            }
          }
        }
      }

      return {
        output:
          "No code snippets or documentation found. Please try a different query, be more specific about the library or programming concept, or check the spelling of framework names.",
        title: `Code search: ${params.query}`,
        metadata: {},
      }
    } catch (error) {
      clearTimeout(timeoutId)

      if (error instanceof Error && error.name === "AbortError") {
        throw new Error("Code search request timed out")
      }

      throw error
    }
  },
})
