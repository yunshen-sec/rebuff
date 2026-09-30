from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from langchain_core.vectorstores import VectorStore

# The vector-database check is optional: importing pinecone/langchain at module scope
# made the whole package unimportable for anyone who only uses the heuristic and
# language-model checks, and `langchain.vectorstores.pinecone` no longer exists in
# langchain >= 0.2. These dependencies are therefore imported lazily, inside the one
# function that needs them.


def _import_pinecone_vector_store() -> Any:
    """Return the Pinecone vector-store class, preferring the current package."""
    try:
        from langchain_pinecone import PineconeVectorStore

        return PineconeVectorStore
    except ImportError:
        pass
    try:  # langchain < 0.2 layout
        from langchain.vectorstores.pinecone import Pinecone as LegacyPinecone

        return LegacyPinecone
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "The vector-database check needs a Pinecone integration. "
            "Install it with: pip install langchain-pinecone pinecone"
        ) from exc


# https://api.python.langchain.com/en/latest/vectorstores/langchain.vectorstores.pinecone.Pinecone.html
def detect_pi_using_vector_database(
    input: str, similarity_threshold: float, vector_store: "VectorStore"
) -> Dict:
    """
    Detects Prompt Injection using similarity search with vector database.

    Args:
        input (str): user input to be checked for prompt injection
        similarity_threshold (float): The threshold for similarity between entries in vector database and the user input.
        vector_store (VectorStore): Vector database of prompt injections

    Returns:
        Dict (str, Union[float, int]): top_score (float) that contains the highest score wrt similarity between vector database and the user input.
                                        count_over_max_vector_score (int) holds the count for times the similarity score (between vector database and the user input)
                                        came out more than the top_score and similarty_threshold.
    """

    top_k = 20
    results = vector_store.similarity_search_with_score(input, top_k)

    top_score = 0
    count_over_max_vector_score = 0

    for _, score in results:
        if score is None:
            continue

        if score > top_score:
            top_score = score

        if score >= similarity_threshold and score > top_score:
            count_over_max_vector_score += 1

    vector_score = {
        "top_score": top_score,
        "count_over_max_vector_score": count_over_max_vector_score,
    }

    return vector_score


def init_pinecone(api_key: str, index: str, openai_api_key: str) -> "VectorStore":
    """
    Initializes connection with the Pinecone vector database using existing (rebuff) index.

    Args:
        api_key (str): Pinecone API key
        index (str): Pinecone index name
        openai_api_key (str): Open AI API key

    Returns:
        vector_store (VectorStore)

    """
    if not api_key:
        raise ValueError("Pinecone apikey definition missing")

    import pinecone
    from langchain_openai import OpenAIEmbeddings

    vector_store_cls = _import_pinecone_vector_store()

    pc = pinecone.Pinecone(api_key=api_key)
    pc_index = pc.Index(index)

    openai_embeddings = OpenAIEmbeddings(
        openai_api_key=openai_api_key, model="text-embedding-ada-002"
    )

    vector_store = vector_store_cls(pc_index, openai_embeddings, text_key="input")

    return vector_store
