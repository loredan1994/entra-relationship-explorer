import { NextRequest } from "next/server";
import { loadEvidencePacket } from "@/server/evidence-packet";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const packet = await loadEvidencePacket(request, "evidence_packet_json");
  if (packet instanceof Response) return packet;
  return new Response(JSON.stringify(packet, null, 2), { headers: {
    "content-type": "application/vnd.entra-explorer.evidence+json; charset=utf-8",
    "content-disposition": `attachment; filename="entra-${packet.packetType}-evidence-${packet.snapshot.scannedAt.slice(0, 10)}.json"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  } });
}
