# import torch
# import dgl

# print("PyTorch:", torch.__version__)
# print("DGL:", dgl.__version__)

# g = dgl.graph(([0, 1], [1, 2]), num_nodes=3)
# g.ndata["h"] = torch.ones(3, 4)

# print("Nodes:", g.num_nodes())
# print("Edges:", g.num_edges())
# print("DGL import and graph creation: OK")

import tempfile
import torch
import dgl

# print("PyTorch:", torch.__version__)
# print("DGL:", dgl.__version__)

# g = dgl.graph(
#     ([0, 1, 2], [1, 2, 0]),
#     num_nodes=3
# )

# g = dgl.add_self_loop(g)
# g.ndata["features"] = torch.randn(3, 16)

# with tempfile.TemporaryDirectory() as tmp:
#     path = f"{tmp}/test_graph.bin"

#     dgl.save_graphs(path, [g])
#     restored = dgl.load_graphs(path)[0][0]

#     print("Restored nodes:", restored.num_nodes())
#     print("Restored edges:", restored.num_edges())

# gat = dgl.nn.GATConv(
#     in_feats=16,
#     out_feats=8,
#     num_heads=2
# )

# output = gat(g, g.ndata["features"])

# print("GAT output shape:", output.shape)
# print("SCVdet basic DGL operations: OK")

pg = "/home/rz.lekeufack/Rosmael/VulPairBench/models/SCVdet/sourcescripts/storage/cache/Graph/pairvul_top10_svuldet_codebert_pdg+raw/p0e24f3ee4d2a1eb99a83__before"

g = dgl.load_graphs(pg)[0][0]

print(g)

print("_RANDFEAT:", g.ndata['_RANDFEAT'])