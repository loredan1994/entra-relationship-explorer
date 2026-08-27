import { renderEvidencePacketMarkdown } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { loadEvidencePacket } from "@/server/evidence-packet";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const packet = await loadEvidencePacket(request, "evidence_packet_markdown");
  if (packet instanceof Response) return packet;
  return new Response(renderEvidencePacketMarkdown(packet), { headers: {
    "content-type": "text/markdown; charset=utf-8",
    "content-disposition": `attachment; filename="entra-${packet.packetType}-evidence-${packet.snapshot.scannedAt.slice(0, 10)}.md"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  } });
}
